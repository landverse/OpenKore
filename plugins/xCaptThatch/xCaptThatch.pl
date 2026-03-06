# ============================================================================
# xCaptThatch — Automated Landverse Login + Encryption Proxy Plugin
# ============================================================================
# This plugin automates the Landverse login flow for XKore 0 mode:
#
# Config options (in config.txt):
#   landverseRelay 1              — enable relay mode
#   landverseGameExe "E:\...\Ragexe.exe" 1rag1  — full command to launch game
#   landverseRelayPort            — relay port (auto-allocated or fallback 7779)
#   landverseEncryptPort          — encrypt port (auto-allocated or fallback 7780)
#   landverseServerPort 7770      — xCaptThatchServer control port
# ============================================================================

package xCaptThatch;

use strict;
use warnings;

use Plugins;
use Globals qw($net $conState $conState_tries %config %masterServers %timeout %timeout_ex $masterServer $messageSender $accountID);
use Log qw(message debug warning error);
use Translation qw(T TF);
use Network;
use Fcntl qw(:flock);
use File::Spec;
use File::Basename;
use IO::Socket::INET;
use IO::Select;
use JSON::PP ();

my $PLUGIN_NAME = 'xCaptThatch';
my $VERSION     = '9.0';

use constant {
    STATE_IDLE       => 'idle',
    STATE_ACQUIRING  => 'acquiring_lock',
    STATE_LAUNCHING  => 'launching_game',
    STATE_WAITING    => 'waiting_relay',
    STATE_CONNECTED  => 'connected',
    STATE_DONE       => 'session_received',
};

my $state           = STATE_IDLE;
my $game_pid        = 0;
my $lock_fh         = undef;
my $launch_time     = 0;
my $wait_start      = 0;
my $login_attempts  = 0;
my $relay_port      = 0;
my $encrypt_port    = 0;
my $server_port     = 7770;
my $lock_file       = '';
my $block_connect   = 0;
my $_relay_msg_shown = 0;
my $_ports_allocated = 0;
my $_bot_id          = 0;
my $_last_queue_log  = 0;
my $_license_ok      = 0;

Plugins::register($PLUGIN_NAME, "Automated Landverse login v$VERSION", \&onUnload);

my $hooks = Plugins::addHooks(
    ['checkConnection',             \&onCheckConnection],
    ['Network::serverConnect/master', \&onMasterConnected],
    ['packet/account_server_info',  \&onAccountServerInfo],
    ['in_game',                     \&onInGame],
    ['mainLoop_pre',                \&onMainLoopPre],
);

message "[$PLUGIN_NAME] Loaded v$VERSION (multi-bot with xCaptThatchServer)\n", 'system';

sub _init {
    return unless $config{landverseRelay};

    $server_port = $config{landverseServerPort} || 7770;
    
    _checkServerLicense();
    
    _allocatePorts();

    if (!$_ports_allocated) {
        $encrypt_port = $config{landverseEncryptPort} || 7780;
        $relay_port   = $config{landverseRelayPort}   || 7779;
        warning "[$PLUGIN_NAME] xCaptThatchServer unavailable, using static ports (encrypt=$encrypt_port, relay=$relay_port)\n";
    }
    
    $config{landverseEncryptPort} = $encrypt_port;
    $config{landverseRelayPort}   = $relay_port;
    
    if ($masterServer && ref($masterServer) eq 'HASH') {
        $masterServer->{port} = $relay_port;
        message "[$PLUGIN_NAME] masterServer port updated to $relay_port\n", 'system';
    }
    
    my $tmpdir = $ENV{TEMP} || $ENV{TMP} || '.';
    $lock_file = File::Spec->catfile($tmpdir, 'xCaptThatch_login.lock');

    message "[$PLUGIN_NAME] Relay mode active (encrypt=$encrypt_port, relay=$relay_port)\n", 'system';
    message "[$PLUGIN_NAME] Lock file in temp directory.\n", 'system';
}

my $_initialized = 0;


sub onMainLoopPre {
    if (!$_initialized && $config{landverseRelay}) {
        _init();
        $_initialized = 1;
    }
    return unless $config{landverseRelay};
    
    if ($state eq STATE_ACQUIRING) {
        _tryAcquireLock();
    }
    elsif ($state eq STATE_LAUNCHING) {
        _checkGameLaunched();
    }
    elsif ($state eq STATE_WAITING) {
        _checkRelayReady();
    }
}

sub onCheckConnection {
    my (undef, $args) = @_;
    return unless $config{landverseRelay};
    
    if ($net && $net->getState() == Network::NOT_CONNECTED) {
        if ($state eq STATE_IDLE) {
            if ($game_pid) {
                message "[$PLUGIN_NAME] Re-login needed, killing old game process (PID=$game_pid)...\n", 'connection';
                _killGame();
            }
            $state = STATE_ACQUIRING;
            $block_connect = 1;
            $login_attempts++;
            message "[$PLUGIN_NAME] Login needed (attempt #$login_attempts), acquiring lock...\n", 'connection';
        }

        if ($block_connect) {
            $args->{return} = 1;
        }
    }
}

sub onMasterConnected {
    return unless $config{landverseRelay};

    if ($state eq STATE_WAITING || $state eq STATE_CONNECTED) {
        $state = STATE_CONNECTED;
        message "[$PLUGIN_NAME] Connected, credentials sent.\n", 'connection';
        message "[$PLUGIN_NAME] Waiting for ASI to automate login...\n", 'connection';
    }
}

sub onAccountServerInfo {
    return unless $config{landverseRelay};

    message "[$PLUGIN_NAME] Login received from relay!\n", 'success';
    $state = STATE_DONE;
    message "[$PLUGIN_NAME] Game stays alive for encryption service (port $encrypt_port)\n", 'connection';
    _releaseLock();

    $state = STATE_IDLE;
    $block_connect = 0;
}

sub onInGame {
    return unless $config{landverseRelay};

    if ($login_attempts > 0) {
        message "[$PLUGIN_NAME] Successfully in game! (took $login_attempts attempt(s))\n", 'success';
        $login_attempts = 0;
    }
}

sub onUnload {
    _freePorts();
    _killGame();
    _releaseLock();
    Plugins::delHooks($hooks) if $hooks;
    message "[$PLUGIN_NAME] Unloaded (game process terminated, ports freed)\n", 'system';
}

sub _tryAcquireLock {
    if (!$lock_fh) {
        if (!sysopen($lock_fh, $lock_file, Fcntl::O_CREAT() | Fcntl::O_RDWR())) {
            warning "[$PLUGIN_NAME] Cannot open lock file: $!\n";
            $state = STATE_LAUNCHING;
            _launchGame();
            return;
        }
    }

    if (flock($lock_fh, LOCK_EX | LOCK_NB)) {
        seek($lock_fh, 0, 0);
        truncate($lock_fh, 0);
        print $lock_fh "$$\n" . time() . "\n";
        $lock_fh->flush() if $lock_fh->can('flush');

        message "[$PLUGIN_NAME] Lock acquired, launching game...\n", 'connection';
        $state = STATE_LAUNCHING;
        _launchGame();
    }
    else {
        if (!$wait_start) {
            $wait_start = time();
            message "[$PLUGIN_NAME] Another bot is logging in, waiting in queue...\n", 'connection';
        }

        my $elapsed = time() - $wait_start;
        
        my $stale = 0;
        eval {
            seek($lock_fh, 0, 0);
            my $pid_line = <$lock_fh>;
            my $time_line = <$lock_fh>;
            if ($pid_line) {
                chomp($pid_line);
                my $holder_pid = int($pid_line);
                if ($holder_pid > 0 && !kill(0, $holder_pid)) {
                    $stale = 1;
                    warning "[$PLUGIN_NAME] Lock holder (PID=$holder_pid) is dead, forcing lock...\n";
                }
                if ($time_line) {
                    chomp($time_line);
                    my $lock_age = time() - int($time_line);
                    if ($lock_age > 90) {
                        $stale = 1;
                        warning "[$PLUGIN_NAME] Lock is ${lock_age}s old (holder PID=$holder_pid), forcing...\n";
                    }
                }
            }
        };

        if ($stale) {
            close($lock_fh) if $lock_fh;
            $lock_fh = undef;
            $wait_start = 0;
            return;
        }
        
        if ($elapsed > 180) {
            warning "[$PLUGIN_NAME] Lock wait timeout (180s), forcing...\n";
            close($lock_fh) if $lock_fh;
            $lock_fh = undef;
            $wait_start = 0;
        }
        elsif ($elapsed > 0 && int($elapsed) % 15 == 0 && int($elapsed) != $_last_queue_log) {
            message "[$PLUGIN_NAME] Still waiting for lock... (${elapsed}s)\n", 'connection';
            $_last_queue_log = int($elapsed);
        }
    }
}

sub _launchGame {
    my $gameCmd = $config{landverseGameExe};
    unless ($gameCmd) {
        error "[$PLUGIN_NAME] landverseGameExe not configured!\n";
        error "[$PLUGIN_NAME] Set in config.txt: landverseGameExe E:\\path\\to\\Ragexe.exe 1rag1\n";
        $state = STATE_IDLE;
        $block_connect = 0;
        _releaseLock();
        return;
    }
    
    my ($exe, $args);
    if ($gameCmd =~ /^"([^"]+)"\s*(.*)$/) {
        $exe = $1;
        $args = $2;
    } elsif ($gameCmd =~ /^(\S+\.exe)\s*(.*)$/i) {
        $exe = $1;
        $args = $2;
    } else {
        $exe = $gameCmd;
        $args = '';
    }

    my $gameDir = dirname($exe);

    message "[$PLUGIN_NAME] Launching: $exe $args\n", 'connection';
    message "[$PLUGIN_NAME] Working dir: $gameDir\n", 'connection';
    message "[$PLUGIN_NAME] Env: XCAPTTHATCH_ENCRYPT_PORT=$encrypt_port, XCAPTTHATCH_RELAY_PORT=$relay_port\n", 'connection';

    $ENV{XCAPTTHATCH_ENCRYPT_PORT} = $encrypt_port;
    $ENV{XCAPTTHATCH_RELAY_PORT}   = $relay_port;
    $ENV{XCAPTTHATCH_SERVER_PORT}  = $server_port;
    my $plugin_dir = dirname(File::Spec->rel2abs(__FILE__));
    my $repo_root  = dirname(dirname($plugin_dir));
    my $portal_dir = File::Spec->catfile($repo_root, 'xCaptThatch');
    if (-f File::Spec->catfile($portal_dir, 'portal.dll')) {
        $ENV{XCAPTTHATCH_PORTAL_DIR} = $portal_dir;
        message "[$PLUGIN_NAME] Portal dir: $portal_dir\n", 'system';
    }
    
    require Cwd;
    my $savedDir = Cwd::getcwd();

    eval {
        chdir($gameDir) or die "Cannot chdir to $gameDir: $!";
        my $basename = basename($exe);
        if ($args) {
            $game_pid = system(1, "\"$exe\" $args");
        } else {
            $game_pid = system(1, "\"$exe\"");
        }

        chdir($savedDir);
    };

    if ($@ || !$game_pid) {
        error "[$PLUGIN_NAME] Failed to launch game: $@\n";
        chdir($savedDir) if $savedDir;
        $state = STATE_IDLE;
        $block_connect = 0;
        _releaseLock();
        return;
    }

    message "[$PLUGIN_NAME] Game launched, PID=$game_pid\n", 'connection';
    $launch_time = time();
    $state = STATE_WAITING;
    $wait_start = time();
}

sub _checkGameLaunched {
    if (time() - $launch_time > 30) {
        error "[$PLUGIN_NAME] Game launch timeout\n";
        _killGame();
        _releaseLock();
        $state = STATE_IDLE;
        $block_connect = 0;
    }
}

sub _checkRelayReady {
    if ($game_pid && !kill(0, $game_pid)) {
        warning "[$PLUGIN_NAME] Game process died unexpectedly\n";
        _releaseLock();
        $state = STATE_IDLE;
        $block_connect = 0;
        $game_pid = 0;
        return;
    }

    my $elapsed = time() - $wait_start;
    if ($elapsed < 3) {
        return;
    }

    if (!$_relay_msg_shown) {
        message "[$PLUGIN_NAME] Probing encrypt service on port $encrypt_port...\n", 'connection';
        $_relay_msg_shown = 1;
    }
    
    my $ready = 0;
    eval {
        my $sock = IO::Socket::INET->new(
            PeerAddr => '127.0.0.1',
            PeerPort => $encrypt_port,
            Proto    => 'tcp',
            Timeout  => 1,
        );
        if ($sock) {
            $sock->close();
            $ready = 1;
        }
    };

    if ($ready) {
        message "[$PLUGIN_NAME] Encrypt service ready on port $encrypt_port (${elapsed}s). Allowing connection.\n", 'connection';
        $block_connect = 0;
        $state = STATE_CONNECTED;
        $_relay_msg_shown = 0;
        $conState_tries = undef;
        $timeout_ex{master}{time} = 0;
        $timeout_ex{master}{timeout} = 0;
        return;
    }
    if ($elapsed > 60) {
        error "[$PLUGIN_NAME] Encrypt service not ready after 60s, aborting\n";
        _killGame();
        _releaseLock();
        $state = STATE_IDLE;
        $block_connect = 0;
        $_relay_msg_shown = 0;
    } elsif ($elapsed > 5 && int($elapsed) % 5 == 0) {
        debug "[$PLUGIN_NAME] Still waiting for encrypt service... (${elapsed}s)\n", 'connection';
    }
}

sub _killGame {
    return unless $game_pid;

    message "[$PLUGIN_NAME] Killing game process (PID=$game_pid)...\n", 'connection';
    my $quit_sent = 0;
    eval {
        if ($messageSender && $messageSender->can('shutdownGame')) {
            my $ack = $messageSender->shutdownGame();
            if ($ack) {
                message "[$PLUGIN_NAME] QUIT sent (ack: $ack)\n", 'connection';
                $quit_sent = 1;
            }
        }
    };
    
    if (!$quit_sent) {
        eval {
            my $port = $encrypt_port || $config{landverseEncryptPort} || 7780;
            my $sock = IO::Socket::INET->new(
                PeerAddr => '127.0.0.1',
                PeerPort => $port,
                Proto    => 'tcp',
                Timeout  => 2,
            );
            if ($sock) {
                $sock->send("QUIT");
                my $ack = '';
                $sock->read($ack, 4);
                $sock->close();
                message "[$PLUGIN_NAME] QUIT sent via new socket (ack: $ack)\n", 'connection';
                $quit_sent = 1;
            }
        };
    }
    
    if ($quit_sent) {
        for my $i (1..10) {
            last unless kill(0, $game_pid);
            select(undef, undef, undef, 0.2) if $i < 10;
        }
    }
    
    if ($game_pid && kill(0, $game_pid)) {
        message "[$PLUGIN_NAME] Process still alive, force killing...\n", 'connection';
        system("taskkill /F /T /PID $game_pid >nul 2>&1");
    }

    $game_pid = 0;
}

sub _releaseLock {
    if ($lock_fh) {
        flock($lock_fh, Fcntl::LOCK_UN());
        close($lock_fh);
        $lock_fh = undef;
    }
    $wait_start = 0;
    $_last_queue_log = 0;
}

END {
    if ($_ports_allocated) {
        eval { _freePorts(); };
    }
    if ($lock_fh) {
        eval { flock($lock_fh, Fcntl::LOCK_UN()); close($lock_fh); };
    }
}

sub _checkServerLicense {
    my $resp = _serverCommand('STATUS');
    if (!$resp) {
        warning "[$PLUGIN_NAME] Cannot reach xCaptThatchServer for license check\n";
        $_license_ok = 0;
        return;
    }

    eval {
        my $status = JSON::PP->new->utf8->decode($resp);
        if ($status && ref($status->{license}) eq 'HASH') {
            if ($status->{license}{valid} eq 'yes') {
                $_license_ok = 1;
                my $slots = $status->{license}{slots} || '?';
                message "[$PLUGIN_NAME] Server license OK (slots: $slots)\n", 'system';
            } else {
                $_license_ok = 0;
                error "[$PLUGIN_NAME] Server reports INVALID license!\n";
                error "[$PLUGIN_NAME] Start xCaptThatchServer with a valid license first.\n";
            }
        } else {
            $_license_ok = 1;
            warning "[$PLUGIN_NAME] Server does not report license status (old version?)\n";
        }
    };
    if ($@) {
        warning "[$PLUGIN_NAME] Failed to parse server STATUS: $@\n";
        $_license_ok = 1;
    }
}

sub _serverCommand {
    my ($cmd) = @_;
    my $response;
    eval {
        my $sock = IO::Socket::INET->new(
            PeerAddr => '127.0.0.1',
            PeerPort => $server_port,
            Proto    => 'tcp',
            Timeout  => 3,
        );
        if ($sock) {
            $sock->print("$cmd\n");
            $sock->flush();

            if (uc($cmd) eq 'STATUS') {
                my $sel = IO::Select->new($sock);
                $response = '';
                while ($sel->can_read(3)) {
                    my $buf;
                    my $n = sysread($sock, $buf, 8192);
                    last if !defined($n) || $n == 0;
                    $response .= $buf;
                    last if $response =~ /\}\s*$/s;
                }
                $response = undef if $response eq '';
            } else {
                $response = <$sock>;
            }
            chomp($response) if defined $response;
            $sock->close();
        }
    };
    if ($@) {
        debug "[$PLUGIN_NAME] Server command '$cmd' failed: $@\n", 'connection';
    }
    return $response;
}

sub _allocatePorts {
    my $resp = _serverCommand('ALLOC_BOT');
    if ($resp && $resp =~ /^BOT:(\d+):(\d+):(\d+)$/) {
        $_bot_id      = int($1);
        $encrypt_port = int($2);
        $relay_port   = int($3);
        $_ports_allocated = 1;
        message "[$PLUGIN_NAME] Bot #$_bot_id allocated (encrypt=$encrypt_port, relay=$relay_port)\n", 'system';
    }
    elsif ($resp && $resp =~ /^PORT:(\d+)$/) {
        $encrypt_port = int($1);
        my $resp2 = _serverCommand('ALLOC');
        if ($resp2 && $resp2 =~ /^PORT:(\d+)$/) {
            $relay_port = int($1);
            $_ports_allocated = 1;
            $_bot_id = 0;
            warning "[$PLUGIN_NAME] Using legacy ALLOC (server too old for ALLOC_BOT)\n";
            message "[$PLUGIN_NAME] Ports allocated (encrypt=$encrypt_port, relay=$relay_port)\n", 'system';
        } else {
            warning "[$PLUGIN_NAME] Failed to allocate relay port (response: " . ($resp2 || 'none') . ")\n";
            _serverCommand("FREE:$encrypt_port");
            $encrypt_port = 0;
        }
    }
    else {
        warning "[$PLUGIN_NAME] Failed to allocate bot (response: " . ($resp || 'none') . ")\n";
    }
}

sub _freePorts {
    return unless $_ports_allocated;

    if ($_bot_id) {
        my $r = _serverCommand("FREE_BOT:$_bot_id");
        debug "[$PLUGIN_NAME] Freed bot #$_bot_id: " . ($r || 'no response') . "\n", 'connection';
    } else {
        if ($encrypt_port) {
            my $r = _serverCommand("FREE:$encrypt_port");
            debug "[$PLUGIN_NAME] Freed encrypt port $encrypt_port: " . ($r || 'no response') . "\n", 'connection';
        }
        if ($relay_port) {
            my $r = _serverCommand("FREE:$relay_port");
            debug "[$PLUGIN_NAME] Freed relay port $relay_port: " . ($r || 'no response') . "\n", 'connection';
        }
    }

    $_ports_allocated = 0;
    $_bot_id = 0;
    message "[$PLUGIN_NAME] Bot freed back to xCaptThatchServer\n", 'system';
}

1;
