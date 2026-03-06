#!/usr/bin/perl
# ============================================================================
# xCaptThatchServer — Port Allocation Server for Multi-Bot xCaptThatch
# ============================================================================
#
# Manages encryption service port allocation for multiple game clients.
# Each bot requests a unique port; the server tracks which ports are in use.
#
# Integrates with xcaptainPanel for license validation and
# slot-based enforcement.
#
# Usage:
#   perl xCaptThatchServer.pl
#
# The server also periodically checks if allocated ports are still in use
# and auto-frees ports whose game processes have died.
# ============================================================================

use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Getopt::Long;
use POSIX qw(strftime);
use JSON::PP ();
use File::Spec;
use File::Basename;
my $CONTROL_PORT   = 7770;
my $PORT_MIN       = 7780;
my $PORT_MAX       = 7880;

GetOptions(
    'port=i'           => \$CONTROL_PORT,
    'min=i'            => \$PORT_MIN,
    'max=i'            => \$PORT_MAX,
) or die "Usage: $0 [--port=7770] [--min=7780] [--max=7880]\n";

my $VERSION = '2.0';

sub logmsg {
    my $ts = strftime("%H:%M:%S", localtime);
    print "[$ts] @_\n";
}
my %allocations;
my %bot_allocations;
my $running = 1;
my $portal_loaded   = 0;
my $portal_valid    = 0;
my $portal_dll_path = '';
my %_api;

sub _loadPortalDll {
    my $script_dir = dirname(File::Spec->rel2abs(__FILE__));
    $portal_dll_path = File::Spec->catfile($script_dir, 'portal.dll');

    unless (-f $portal_dll_path) {
        logmsg "WARNING: portal.dll not found at $portal_dll_path";
        logmsg "WARNING: Running WITHOUT license validation!";
        return 0;
    }

    eval {
        require Win32::API;
        Win32::API->import();
    };
    if ($@) {
        logmsg "WARNING: Win32::API not available: $@";
        logmsg "WARNING: Install with: cpan Win32::API";
        logmsg "WARNING: Running WITHOUT license validation!";
        return 0;
    }

    logmsg "Loading portal.dll from $portal_dll_path";
    eval {
        $_api{init} = Win32::API->new($portal_dll_path, 'int __cdecl portal_init(char* apiUrl, char* portalSecret)')
            or die "Cannot import portal_init: $^E";
        $_api{validate} = Win32::API->new($portal_dll_path, 'int __cdecl portal_validate()')
            or die "Cannot import portal_validate: $^E";
        $_api{activate} = Win32::API->new($portal_dll_path, 'int __cdecl portal_activate()')
            or die "Cannot import portal_activate: $^E";
        $_api{get_hwid} = Win32::API->new($portal_dll_path, 'int __cdecl portal_get_hwid(char* buf, int bufsize)')
            or die "Cannot import portal_get_hwid: $^E";
        $_api{get_license_id} = Win32::API->new($portal_dll_path, 'int __cdecl portal_get_license_id(char* buf, int bufsize)')
            or die "Cannot import portal_get_license_id: $^E";
        $_api{get_session_secret} = Win32::API->new($portal_dll_path, 'int __cdecl portal_get_session_secret(char* buf, int bufsize)')
            or die "Cannot import portal_get_session_secret: $^E";
        $_api{get_slots} = Win32::API->new($portal_dll_path, 'int __cdecl portal_get_slots()')
            or die "Cannot import portal_get_slots: $^E";
        $_api{get_active_slots} = Win32::API->new($portal_dll_path, 'int __cdecl portal_get_active_slots()')
            or die "Cannot import portal_get_active_slots: $^E";
        $_api{claim_slot} = Win32::API->new($portal_dll_path, 'int __cdecl portal_claim_slot(char* out_nonce, int nonce_bufsize)')
            or die "Cannot import portal_claim_slot: $^E";
        $_api{release_slot} = Win32::API->new($portal_dll_path, 'int __cdecl portal_release_slot(char* nonce)')
            or die "Cannot import portal_release_slot: $^E";
        $_api{heartbeat_slot} = Win32::API->new($portal_dll_path, 'int __cdecl portal_heartbeat_slot(char* nonce)')
            or die "Cannot import portal_heartbeat_slot: $^E";
        $_api{revalidate} = Win32::API->new($portal_dll_path, 'int __cdecl portal_revalidate()')
            or die "Cannot import portal_revalidate: $^E";
        $_api{shutdown} = Win32::API->new($portal_dll_path, 'void __cdecl portal_shutdown()')
            or die "Cannot import portal_shutdown: $^E";
        $_api{get_last_error} = Win32::API->new($portal_dll_path, 'int __cdecl portal_get_last_error(char* buf, int bufsize)')
            or die "Cannot import portal_get_last_error: $^E";
        $_api{sign_challenge} = Win32::API->new($portal_dll_path, 'int __cdecl portal_sign_challenge(char* challenge, char* out_sig, int sig_bufsize)')
            or die "Cannot import portal_sign_challenge: $^E";
        $_api{verify_challenge} = Win32::API->new($portal_dll_path, 'int __cdecl portal_verify_challenge(char* challenge, char* signature)')
            or die "Cannot import portal_verify_challenge: $^E";
        $_api{get_session_proof} = Win32::API->new($portal_dll_path, 'int __cdecl portal_get_session_proof(char* out_buf, int bufsize)')
            or die "Cannot import portal_get_session_proof: $^E";
    };

    if ($@) {
        logmsg "ERROR loading portal.dll functions: $@";
        return 0;
    }

    $portal_loaded = 1;
    return 1;
}

sub _initPortal {
    return 0 unless $portal_loaded;
    my $result = $_api{init}->Call("", "");
    if ($result != 0) {
        my $err = _portalLastError();
        logmsg "ERROR: portal_init failed: $err";
        logmsg "Ensure portal.dll was compiled with valid PORTAL_EMBEDDED_URL/SECRET";
        return 0;
    }

    logmsg "Portal initialized successfully";
    
    my $hwid_buf = "\0" x 128;
    if ($_api{get_hwid}->Call($hwid_buf, 128) == 0) {
        $hwid_buf =~ s/\0+$//;
        logmsg "HWID: $hwid_buf";
    }

    return 1;
}

sub _validateLicense {
    return 1 unless $portal_loaded;

    logmsg "Validating license...";
    my $result = $_api{validate}->Call();

    if ($result == 0) {
        $portal_valid = 1;
        my $slots = $_api{get_slots}->Call();
        my $lid_buf = "\0" x 128;
        $_api{get_license_id}->Call($lid_buf, 128);
        $lid_buf =~ s/\0+$//;
        logmsg "License VALID: $lid_buf (slots: $slots)";
        return 1;
    }
    elsif ($result == 2) {
        logmsg "License not bound to this machine. Starting activation...";
        my $act_result = $_api{activate}->Call();
        if ($act_result == 0) {
            $portal_valid = 1;
            my $slots = $_api{get_slots}->Call();
            logmsg "Activation complete! (slots: $slots)";
            return 1;
        }
        else {
            my $err = _portalLastError();
            logmsg "Activation FAILED: $err";
            return 0;
        }
    }
    else {
        my $err = _portalLastError();
        logmsg "License validation FAILED (code=$result): $err";
        return 0;
    }
}

sub _portalLastError {
    return 'unknown' unless $portal_loaded;
    my $buf = "\0" x 512;
    $_api{get_last_error}->Call($buf, 512);
    $buf =~ s/\0+$//;
    return $buf || 'unknown';
}

sub alloc_port {
    my ($client_addr) = @_;

    for my $port ($PORT_MIN .. $PORT_MAX) {
        next if exists $allocations{$port};

        $allocations{$port} = {
            time        => time(),
            client_addr => $client_addr || 'unknown',
        };

        logmsg "ALLOC port $port for $client_addr (" . _count_active() . " ports active)";
        return $port;
    }
    return undef;
}

sub free_port {
    my ($port) = @_;
    if (exists $allocations{$port}) {
        my $info = $allocations{$port};
        delete $allocations{$port};

        logmsg "FREE port $port (was held by $info->{client_addr}, " . _count_active() . " ports active)";
        return 1;
    }
    return 0;
}

sub alloc_bot {
    my ($client_addr) = @_;
    if ($portal_loaded && $portal_valid) {
        my $max_slots = $_api{get_slots}->Call();
        my $active_bots = _count_active_bots();
        if ($max_slots > 0 && $active_bots >= $max_slots) {
            logmsg "ALLOC_BOT BLOCKED: advisory slot limit ($active_bots/$max_slots) ($client_addr)";
            return undef;
        }
    }
    my $enc_port = alloc_port($client_addr);
    if (!defined $enc_port) {
        logmsg "ALLOC_BOT FAILED: no encrypt port available ($client_addr)";
        return undef;
    }
    my $rel_port = alloc_port($client_addr);
    if (!defined $rel_port) {
        free_port($enc_port);
        logmsg "ALLOC_BOT FAILED: no relay port available ($client_addr)";
        return undef;
    }
    my $bot_id = 1;
    while (exists $bot_allocations{$bot_id}) { $bot_id++; }
    $bot_allocations{$bot_id} = {
        encrypt_port => $enc_port,
        relay_port   => $rel_port,
        time         => time(),
        client_addr  => $client_addr || 'unknown',
    };

    logmsg "ALLOC_BOT #$bot_id: encrypt=$enc_port, relay=$rel_port" .
           " (" . _count_active_bots() . " bots active)";

    return ($bot_id, $enc_port, $rel_port);
}

sub free_bot {
    my ($bot_id) = @_;
    if (exists $bot_allocations{$bot_id}) {
        my $info = $bot_allocations{$bot_id};
        free_port($info->{encrypt_port}) if $info->{encrypt_port};
        free_port($info->{relay_port}) if $info->{relay_port};

        logmsg "FREE_BOT #$bot_id: encrypt=$info->{encrypt_port}, relay=$info->{relay_port}" .
               " (was $info->{client_addr}, " . (_count_active_bots() - 1) . " bots remaining)";

        delete $bot_allocations{$bot_id};
        return 1;
    }
    return 0;
}

sub _count_active_bots {
    return scalar(keys %bot_allocations);
}

sub ping_port {
    my ($port) = @_;
    my $sock = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 1,
    );
    if ($sock) {
        close($sock);
        return 1;
    }
    return 0;
}

sub cleanup_dead_ports {
    my @dead;
    for my $port (keys %allocations) {
        my $info = $allocations{$port};
        my $age = time() - $info->{time};
        next if $age < 30;
        if (!ping_port($port)) {
            push @dead, $port;
        }
    }
    for my $port (@dead) {
        logmsg "CLEANUP: port $port is dead (no listener), auto-freeing";
        my $freed_via_bot = 0;
        for my $bid (keys %bot_allocations) {
            my $binfo = $bot_allocations{$bid};
            if (($binfo->{encrypt_port} && $binfo->{encrypt_port} == $port) ||
                ($binfo->{relay_port} && $binfo->{relay_port} == $port)) {
                logmsg "CLEANUP: port $port belongs to bot #$bid — freeing entire bot";
                free_bot($bid);
                $freed_via_bot = 1;
                last;
            }
        }
        free_port($port) unless $freed_via_bot;
    }
}

sub _count_active {
    return scalar(keys %allocations);
}

sub get_status {
    my %status = (
        version      => $VERSION,
        control_port => $CONTROL_PORT,
        port_range   => "$PORT_MIN-$PORT_MAX",
        total_slots  => ($PORT_MAX - $PORT_MIN + 1),
        active_ports => _count_active(),
        active_bots  => _count_active_bots(),
        allocations  => {},
        bots         => {},
        license      => {
            loaded       => $portal_loaded ? 'yes' : 'no',
            valid        => $portal_valid  ? 'yes' : 'no',
            slots        => $portal_loaded ? $_api{get_slots}->Call() : 0,
            active_slots => $portal_loaded ? $_api{get_active_slots}->Call() : 0,
        },
    );
    for my $port (sort { $a <=> $b } keys %allocations) {
        my $info = $allocations{$port};
        $status{allocations}{$port} = {
            client  => $info->{client_addr},
            age_sec => time() - $info->{time},
            alive   => ping_port($port) ? 'yes' : 'no',
        };
    }
    for my $bid (sort { $a <=> $b } keys %bot_allocations) {
        my $binfo = $bot_allocations{$bid};
        $status{bots}{$bid} = {
            encrypt_port => $binfo->{encrypt_port},
            relay_port   => $binfo->{relay_port},
            client       => $binfo->{client_addr},
            age_sec      => time() - $binfo->{time},
        };
    }
    return \%status;
}

sub handle_command {
    my ($line, $client) = @_;
    $line =~ s/[\r\n]+$//;

    my $addr = $client->peerhost() . ":" . $client->peerport();
    
    if ($line =~ /^CHALLENGE:(.+)$/i) {
        my $challenge_data = $1;
        if (!$portal_loaded) {
            logmsg "CHALLENGE from $addr: portal not loaded";
            return "ERROR:NO_PORTAL\n";
        }
        if (!$portal_valid) {
            logmsg "CHALLENGE from $addr: license not validated";
            return "ERROR:NOT_VALIDATED\n";
        }
        my $sig_buf = "\0" x 128;
        my $result = $_api{sign_challenge}->Call($challenge_data, $sig_buf, 128);
        if ($result == 0) {
            $sig_buf =~ s/\0+$//;
            logmsg "CHALLENGE from $addr: signed OK";
            return "RESPONSE:$sig_buf\n";
        } else {
            my $err = _portalLastError();
            logmsg "CHALLENGE from $addr: sign FAILED ($err)";
            return "ERROR:SIGN_FAILED\n";
        }
    }

    $line = uc($line);

    if ($line eq 'ALLOC') {
        my $port = alloc_port($addr);
        if (defined $port) {
            return "PORT:$port\n";
        } else {
            logmsg "ALLOC FAILED: all ports exhausted ($addr)";
            return "ERROR:NO_PORTS_AVAILABLE\n";
        }
    }
    elsif ($line eq 'ALLOC_BOT') {
        my ($bot_id, $enc_port, $rel_port) = alloc_bot($addr);
        if (defined $bot_id) {
            return "BOT:$bot_id:$enc_port:$rel_port\n";
        } else {
            logmsg "ALLOC_BOT FAILED ($addr)";
            return "ERROR:NO_SLOTS_AVAILABLE\n";
        }
    }
    elsif ($line =~ /^FREE_BOT:(\d+)$/) {
        my $bot_id = int($1);
        if (free_bot($bot_id)) {
            return "OK\n";
        } else {
            return "ERROR:BOT_NOT_ALLOCATED\n";
        }
    }
    elsif ($line =~ /^FREE:(\d+)$/) {
        my $port = int($1);
        if (free_port($port)) {
            return "OK\n";
        } else {
            return "ERROR:PORT_NOT_ALLOCATED\n";
        }
    }
    elsif ($line =~ /^PING:(\d+)$/) {
        my $port = int($1);
        return ping_port($port) ? "ALIVE\n" : "DEAD\n";
    }
    elsif ($line eq 'STATUS') {
        my $status = get_status();
        my $json = eval { JSON::PP->new->utf8->pretty->encode($status) } || '{"error":"json_encode_failed"}';
        return $json . "\n";
    }
    elsif ($line eq 'QUIT') {
        return "BYE\n";
    }
    elsif ($line eq 'SHUTDOWN') {
        logmsg "SHUTDOWN requested by $addr";
        $running = 0;
        return "BYE\n";
    }
    else {
        return "ERROR:UNKNOWN_COMMAND\n";
    }
}

logmsg "===========================================";
logmsg " xCaptThatchServer v$VERSION";
logmsg " Control port: $CONTROL_PORT";
logmsg " Port pool:    $PORT_MIN - $PORT_MAX (" . ($PORT_MAX - $PORT_MIN + 1) . " slots)";
logmsg "===========================================";

if (_loadPortalDll()) {
    if (_initPortal()) {
        if (!_validateLicense()) {
            logmsg "FATAL: License validation failed. Server cannot start.";
            logmsg "Ensure you have a valid license bound to this machine.";
            logmsg "Visit your panel or run the activation flow.";
            die "License validation failed\n";
        }
        logmsg "License validated — slot enforcement active";
    } else {
        logmsg "WARNING: Portal init failed — running without license enforcement";
    }
} else {
    logmsg "WARNING: portal.dll not available — running without license enforcement";
}

my $server = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $CONTROL_PORT,
    Proto     => 'tcp',
    Listen    => 10,
    Reuse     => 1,
) or die "Cannot start server on port $CONTROL_PORT: $!\n";

logmsg "Listening on 127.0.0.1:$CONTROL_PORT";

my $select = IO::Select->new($server);
my $last_cleanup = time();
my $CLEANUP_INTERVAL = 60;

while ($running) {
    my @ready = $select->can_read(5);
    
    if (time() - $last_cleanup > $CLEANUP_INTERVAL) {
        cleanup_dead_ports();
        $last_cleanup = time();
    }

    for my $sock (@ready) {
        if ($sock == $server) {
            my $client = $server->accept();
            next unless $client;
            $client->autoflush(1);
            $select->add($client);
            logmsg "Client connected: " . $client->peerhost() . ":" . $client->peerport();
        }
        else {
            my $line = <$sock>;
            if (!defined $line || $line eq '') {
                logmsg "Client disconnected: " . ($sock->peerhost() || '?') . ":" . ($sock->peerport() || '?');
                $select->remove($sock);
                close($sock);
                next;
            }

            my $response = handle_command($line, $sock);
            eval { $sock->print($response); };
            if ($line =~ /^(QUIT|SHUTDOWN)/i) {
                $select->remove($sock);
                close($sock);
            }
        }
    }
}

logmsg "Server shutting down...";
for my $bid (keys %bot_allocations) {
    free_bot($bid);
}
for my $port (keys %allocations) {
    free_port($port);
}
if ($portal_loaded) {
    eval { $_api{shutdown}->Call(); };
    logmsg "portal.dll shutdown complete";
}
close($server);
logmsg "Goodbye.";

__END__

=head1 NAME

xCaptThatchServer - Port allocation server for multi-bot xCaptThatch

=head1 SYNOPSIS

    perl xCaptThatchServer.pl [--port=7770] [--min=7780] [--max=7799]

=head1 DESCRIPTION

Manages encryption service port allocation for multiple simultaneous game clients.
Each OpenKore bot instance requests a unique port from this server.

Integrates with xcaptainPanel backend for license validation
and challenge-response authentication.

Start this server ONCE before launching any bots.

=cut
