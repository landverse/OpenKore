#!/usr/bin/env perl
#########################################################################
#  This software is open source, licensed under the GNU General Public
#  License, version 2.
#  Basically, this means that you're allowed to modify and distribute
#  this software. However, if you distribute modified versions, you MUST
#  also distribute the source code.
#  See http://www.gnu.org/licenses/gpl.html for the full license.
#
#########################################################################

package main;
use strict;
use FindBin qw($RealBin);
use lib "$RealBin";
use lib "$RealBin/src";
use lib "$RealBin/src/deps";

use Time::HiRes qw(time usleep);
use Carp::Assert;


sub __start {
	use ErrorHandler;
	use XSTools;
	use Utils::Rijndael;
	srand();

	use Translation;
	use Settings qw(%sys);
	use Utils::Exceptions;

	eval "use OpenKoreMod;";
	undef $@;
	parseArguments();
	Settings::loadSysConfig();
	Translation::initDefault($sys{locale});

	use Globals;
	use Interface;
	if (!$interface) {
		$interface = Interface->loadInterface($Settings::interface);
		$interface->title($Settings::NAME);
	}
	selfCheck();

	use Utils::PathFinding;
	require Utils::Win32 if ($^O eq 'MSWin32');
	require 'functions.pl';

	use Modules;
	use Log;
	use Utils;
	use Plugins;
	use FileParsers;
	use Misc;
	use Network::Receive;
	use Network::Send ();
	use Commands;
	use AI;
	use AI::CoreLogic;
	use AI::Attack;
	use Actor;
	use Actor::Player;
	use Actor::Monster;
	use Actor::You;
	use Actor::Party;
	use Actor::Portal;
	use Actor::NPC;
	use Actor::Pet;
	use Actor::Unknown;
	use ActorList;
	use Interface;
	use ChatQueue;
	use TaskManager;
	use Task;
	use Task::WithSubtask;
	use Task::TalkNPC;
	use Utils::Benchmark;
	use Utils::HttpReader;
	use Utils::Whirlpool;
	use Poseidon::Client;
	Modules::register(qw/Utils FileParsers
		Network::Receive Network::Send Misc AI AI::CoreLogic
		AI::Attack AI::Slave AI::Slave::Homunculus AI::Slave::Mercenary
		ChatQueue Actor Actor::Player Actor::Monster Actor::You
		Actor::Party Actor::Unknown Actor::Item Match Utils::Benchmark/);

	Benchmark::begin("Real time") if DEBUG;
	$interface->mainLoop();
	Benchmark::end("Real time") if DEBUG;

	main::shutdown();
}

sub parseArguments {
	eval {
		Settings::parseArguments();
		if ($Settings::options{version}) {
			print "$Settings::versionText\n";
			exit 0;
		}
	};
	if (my $e = caught('IOException', 'ArgumentException')) {
		print "Error: $e\n";
		if ($e->isa('ArgumentException')) {
			print Settings::getUsageText();
		}
		exit 1;
	} elsif ($@) {
		die $@;
	}
}

sub checkEmptyArguments {
	if ( $Settings::options{help} ) {
		print Settings::getUsageText();
		exit 0;
	}
	eval {
		use Getopt::Long;
		local $SIG{__WARN__} = sub { ArgumentException->throw( $_[0] ); };
		Getopt::Long::Configure( 'default' );
		GetOptions();
	};
	if ( my $e = caught( 'IOException', 'ArgumentException' ) ) {
		print "Error: $e\n";
		if ( $e->isa( 'ArgumentException' ) ) {
			print Settings::getUsageText();
		}
		exit 1;
	} elsif ( $@ ) {
		die $@;
	}
}

sub selfCheck {
	use Globals qw($interface);

	if ($^O eq 'MSWin32' && !defined(getprotobyname("tcp"))) {
		$interface->errorDialog(TF(
			"Your Windows TCP/IP stack is broken. Please read\n" .
			"  %s\n" .
			"to learn how to solve this.",
			"https://openkore.com/wiki/Frequently_Asked_Questions#Your_Windows_TCP.2FIP_stack_is_broken"));
		exit 1;
	}
	
	if (-f "$RealBin/Misc.pm") {
		$interface->errorDialog(T("You have old files in the OpenKore folder, which may cause conflicts.\n" .
			"Please delete your entire OpenKore source folder, and redownload everything."));
		exit 1;
	}

	if (!defined &XSTools::majorVersion) {
		$interface->errorDialog(TF("Your version of the XSTools library is too old.\n" .
			"Please upgrade it from %s", "https://misc.openkore.com/"));
		exit 1;
	} elsif (XSTools::majorVersion() != 5) {
		my $error;
		if (defined $ENV{INTERPRETER}) {
			$error = TF("Your version of (wx)start.exe is incompatible.\n" .
				"Please upgrade it from %s", "https://misc.openkore.com/");
		} else {
			$error = TF("Your version of XSTools library is incompatible.\n" .
				"Please upgrade it from %s", "https://misc.openkore.com/");
		}
		$interface->errorDialog($error);
		exit 1;
	} elsif (XSTools::minorVersion() < 8) {
		my $error;
		if (defined $ENV{INTERPRETER}) {
			$error = TF("Your version of (wx)start.exe is too old.\n" .
				"Please upgrade it from %s", "https://misc.openkore.com/")
		} else {
			$error = TF("Your version of the XSTools library is too old.\n" .
				"Please upgrade it from %s", "https://misc.openkore.com/")
		}
		$interface->errorDialog($error);
		exit 1;
	}
}

sub shutdown {
	Plugins::unloadAll();
	if ($bus) {
		$bus->close();
		undef $bus;
	}
	
	Log::message($Settings::versionText);

	if (DEBUG && open(F, ">:utf8", "benchmark-results.txt")) {
		print F Benchmark::results("mainLoop");
		close F;
		print "Benchmark results saved to benchmark-results.txt\n";
	}
		$interface->errorDialog(T("Bye!\n")) if $config{dcPause};
}

if (!defined($ENV{INTERPRETER}) && !$ENV{NO_AUTOSTART}) {
	my $max_retries = $ENV{OPENKORE_MAX_RETRIES} || 5;
	my $retry_delay = $ENV{OPENKORE_RETRY_DELAY} || 3;
	my $attempt = 0;

	$ENV{OPENKORE_AUTO_RETRY} = 1;
	
	$SIG{INT} = sub {
		print "\n[SIGINT] Ctrl+C received. Cleaning up...\n";
		
		eval {
			if (defined $Globals::messageSender && $Globals::messageSender->can('shutdownGame')) {
				my $ack = $Globals::messageSender->shutdownGame();
				print "[SIGINT] Sent QUIT via messageSender (ack: " . ($ack || 'none') . ")\n";
			} else {
				my $enc_port = $ENV{XCAPTTHATCH_ENCRYPT_PORT} || 7780;
				require IO::Socket::INET;
				my $sock = IO::Socket::INET->new(
					PeerAddr => '127.0.0.1',
					PeerPort => $enc_port,
					Proto    => 'tcp',
					Timeout  => 2,
				);
				if ($sock) {
					$sock->send("QUIT");
					my $ack = '';
					$sock->recv($ack, 4);
					$sock->close();
					print "[SIGINT] Sent QUIT via new socket (port $enc_port, ack: $ack)\n";
				}
			}
		};
		eval { Plugins::unloadAll(); };
		eval { main::shutdown(); };
		print "[SIGINT] Bye!\n";
		exit 0;
	};

	while ($attempt < $max_retries) {
		$attempt++;
		eval { __start(); };

		if ($@) {
			my $err = $@;
			eval {
				my $sent = 0;
				if (defined $Globals::messageSender && $Globals::messageSender->can('shutdownGame')) {
					my $ack = $Globals::messageSender->shutdownGame();
					if ($ack) {
						print "[AutoRetry] Sent QUIT via messageSender (ack: $ack)\n";
						$sent = 1;
					}
				}
				if (!$sent) {
					my $enc_port = $ENV{XCAPTTHATCH_ENCRYPT_PORT} || 7780;
					require IO::Socket::INET;
					my $sock = IO::Socket::INET->new(
						PeerAddr => '127.0.0.1',
						PeerPort => $enc_port,
						Proto    => 'tcp',
						Timeout  => 2,
					);
					if ($sock) {
						$sock->send("QUIT");
						my $ack = '';
						$sock->recv($ack, 4);
						$sock->close();
						print "[AutoRetry] Sent QUIT via new socket (port $enc_port, ack: $ack)\n";
					}
				}
				select(undef, undef, undef, 1);
			};
			eval { Plugins::unloadAll(); };
			eval {
				if (defined $Globals::net) {
					$Globals::net->serverDisconnect() if $Globals::net->can('serverDisconnect');
				}
			};
			eval {
				undef $Globals::net;
				undef $Globals::messageSender;
				$Globals::conState = 1;
			};
			
			print "\n[AutoRetry] Crash detected (attempt $attempt/$max_retries).\n";
			print "[AutoRetry] Error: $err\n" if $err !~ /^\s*$/;

			if ($attempt < $max_retries) {
				print "[AutoRetry] Restarting in ${retry_delay}s...\n";
				sleep($retry_delay);
			} else {
				print "[AutoRetry] Max retries ($max_retries) reached. Giving up.\n";
				delete $ENV{OPENKORE_AUTO_RETRY};
				print "Press ENTER to exit.\n";
				<STDIN>;
			}
		} else {
			last;
		}
	}
}

1;
