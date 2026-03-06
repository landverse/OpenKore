package Network::Send::Landverse;
use strict;
use base    qw(Network::Send::kRO::RagexeRE_2021_11_03);
use Globals qw($net %config $masterServer $sessionID2);
use Utils   qw(getTickCount getCoordString);
use Log     qw(debug message);
use IO::Socket::INET;

sub new {
	my ( $class ) = @_;
	my $self = $class->SUPER::new( @_ );

	my %packets = (
		'0C26' => ['master_login', 'a4 Z51 a32 a5', [qw(game_code username password_rijndael flag)]],
		'0BFF' => ['character_move', 'a4', [qw(coordString)]],
		'01D5' => ['npc_talk_text', 'v a4 a*', [qw(len ID text)]],
	);

	$self->{packet_list}{$_} = $packets{$_} for keys %packets;

	my %handlers = qw(
		master_login 0C26
		character_move 0BFF
		npc_talk_text 01D5
	);

	$self->{packet_lut}{$_} = $handlers{$_} for keys %handlers;

	return $self;
}

sub reconstruct_master_login {
	my ( $self, $args ) = @_;

	if ( exists $args->{password} ) {
		for ( Digest::MD5->new ) {
			$_->add( $args->{password} );
			$args->{password_md5}     = $_->clone->digest;
			$args->{password_md5_hex} = $_->hexdigest;
		}

		if ($config{landverseRelay}) {
			$args->{password_rijndael} = pack('a32', $args->{password});
			return;
		}

		my $key      = pack( 'C32', ( 0x06, 0xA9, 0x21, 0x40, 0x36, 0xB8, 0xA1, 0x5B, 0x51, 0x2E, 0x03, 0xD5, 0x34, 0x12, 0x00, 0x06, 0x06, 0xA9, 0x21, 0x40, 0x36, 0xB8, 0xA1, 0x5B, 0x51, 0x2E, 0x03, 0xD5, 0x34, 0x12, 0x00, 0x06 ) );
		my $chain    = pack( 'C32', ( 0x3D, 0xAF, 0xBA, 0x42, 0x9D, 0x9E, 0xB4, 0x30, 0xB4, 0x22, 0xDA, 0x80, 0x2C, 0x9F, 0xAC, 0x41, 0x3D, 0xAF, 0xBA, 0x42, 0x9D, 0x9E, 0xB4, 0x30, 0xB4, 0x22, 0xDA, 0x80, 0x2C, 0x9F, 0xAC, 0x41 ) );
		my $in       = pack( 'a32', $args->{password} );
		my $rijndael = Utils::Rijndael->new;
		$rijndael->MakeKey( $key, $chain, 32, 32 );
		$args->{password_rijndael} = $rijndael->Encrypt( $in, undef, 32, 0 );
	}
}

sub sendMasterLogin {
	my ($self, $username, $password, $master_version, $version) = @_;
	my $hash = pack('C16', map { int(rand(256)) } 1..16);
	my $hash_msg = $self->reconstruct({
		switch => 'client_hash',
		hash => $hash,
	});
	$self->sendToServer($hash_msg);
	my $hexHash = join(' ', map { sprintf("%02X", ord($_)) } split(//, $hash));
	if ($config{landverseRelay}) {
		$self->_sendPlaintextLogin($username, $password, $master_version, $version);
	} elsif ($config{landverseEncrypt}) {
		$self->_sendEncryptedLogin($username, $password, $master_version, $version);
	} else {
		$self->_sendPlaintextLogin($username, $password, $master_version, $version);
	}
}

sub _sendPlaintextLogin {
	my ($self, $username, $password, $master_version, $version) = @_;

	my $msg = $self->reconstruct({
		switch => 'master_login',
		version => $version,
		master_version => $master_version,
		username => $username,
		password => $password,
		game_code => '0011',
		flag => 'G000',
	});

	$self->sendToServer($msg);
	my $sw = uc(unpack("H4", substr($msg, 0, 2)));
	my $mlen = length($msg);
}

sub _sendEncryptedLogin {
	my ($self, $username, $password, $master_version, $version) = @_;

	my $key   = pack('C32', (0x06, 0xA9, 0x21, 0x40, 0x36, 0xB8, 0xA1, 0x5B,
	                          0x51, 0x2E, 0x03, 0xD5, 0x34, 0x12, 0x00, 0x06,
	                          0x06, 0xA9, 0x21, 0x40, 0x36, 0xB8, 0xA1, 0x5B,
	                          0x51, 0x2E, 0x03, 0xD5, 0x34, 0x12, 0x00, 0x06));
	my $chain = pack('C32', (0x3D, 0xAF, 0xBA, 0x42, 0x9D, 0x9E, 0xB4, 0x30,
	                          0xB4, 0x22, 0xDA, 0x80, 0x2C, 0x9F, 0xAC, 0x41,
	                          0x3D, 0xAF, 0xBA, 0x42, 0x9D, 0x9E, 0xB4, 0x30,
	                          0xB4, 0x22, 0xDA, 0x80, 0x2C, 0x9F, 0xAC, 0x41));

	my $rijndael = Utils::Rijndael->new;
	$rijndael->MakeKey($key, $chain, 32, 32);
	my $pw_in  = pack('a32', $password);
	my $pw_enc = $rijndael->Encrypt($pw_in, undef, 32, 0);
	my $payload = pack('a4', '0011')
	            . pack('Z51', $username)
	            . $pw_enc
	            . pack('a5', 'G000');
	$payload .= "\x00" x (128 - length($payload));
	$rijndael->MakeKey($key, $chain, 32, 32);
	my $encrypted = $rijndael->Encrypt($payload, undef, 128, 0);
	my $msg = pack('v', 0x0064) . $encrypted;
	$self->sendToServer($msg);

	my $mlen = length($msg);
	my $hexFirst = join(' ', map { sprintf("%02X", ord($_)) } split(//, substr($msg, 0, 20)));
}

sub sendMapLogin {
	my ($self, $accountID, $charID, $sessionID, $sex) = @_;
	$sex = 0 if ($sex > 1 || $sex < 0);

	my $sid2 = 0;
	if (defined $sessionID2 && length($sessionID2) >= 4) {
		$sid2 = unpack('V', $sessionID2);
	}

	my $msg = $self->reconstruct({
		switch => 'map_login',
		accountID => $accountID,
		charID => $charID,
		sessionID => $sessionID,
		unknown => $sid2,
		tick => getTickCount(),
		sex => $sex,
	});

	$self->sendToServer($msg);
	my $hexSid2 = sprintf("0x%08X", $sid2);
}
my $_encryptSock = undef;

sub _connectEncryptService {
	my ($self) = @_;
	
	if ($_encryptSock) {
		
		my $peername = $_encryptSock->connected;
		return $_encryptSock if $peername;
		$_encryptSock->close();
		$_encryptSock = undef;
		debug "[LANDVERSE] Encrypt socket lost, will reconnect\n", "sendPacket", 2;
	}

	my $port = $config{landverseEncryptPort} || 7780;
	$_encryptSock = IO::Socket::INET->new(
		PeerAddr => '127.0.0.1',
		PeerPort => $port,
		Proto    => 'tcp',
		Timeout  => 3,
	);
	if (!$_encryptSock) {
		debug "[LANDVERSE] Encryption service connect failed (port $port): $!\n", "sendPacket", 2;
		return undef;
	}
	$_encryptSock->sockopt(Socket::TCP_NODELAY, 1) if defined &Socket::TCP_NODELAY;
	return $_encryptSock;
}

sub _disconnectEncryptService {
	if ($_encryptSock) {
		$_encryptSock->close();
		$_encryptSock = undef;
		debug "[LANDVERSE] Encrypt session closed (counter reset on next connect)\n", "sendPacket", 2;
	}
}

sub shutdownGame {
	my ($self) = @_;
	if ($_encryptSock && $_encryptSock->connected) {
		eval {
			$_encryptSock->send("QUIT");
			my $ack = '';
			$_encryptSock->read($ack, 4);
			$_encryptSock->close();
			$_encryptSock = undef;
			message "[LANDVERSE] Sent QUIT via persistent socket (ack: $ack)\n", "connection";
			return $ack;
		};
		$_encryptSock = undef;
	}
	eval {
		require IO::Socket::INET;
		my $port = $config{landverseEncryptPort} || 7780;
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
			message "[LANDVERSE] Sent QUIT via new socket (ack: $ack)\n", "connection";
			return $ack;
		}
	};

	return undef;
}

sub _encryptWalkPayload {
	my ($self, $plaintext4) = @_;

	my $sock = $self->_connectEncryptService();
	return undef unless $sock;

	my $sent = $sock->send($plaintext4);
	if (!defined $sent || $sent != 4) {
		$self->_disconnectEncryptService();
		return undef;
	}

	my $encrypted = '';
	my $got = $sock->read($encrypted, 4);

	if (!defined $got || $got != 4) {
		$self->_disconnectEncryptService();
		return undef;
	}

	return $encrypted;
}

sub sendMove {
	my ($self, $x, $y) = @_;
	require Time::HiRes;
	my $now = Time::HiRes::time();
	if (!defined $self->{_lastMoveTime}) {
		$self->{_lastMoveTime} = 0;
		$self->{_lastMoveX}    = -1;
		$self->{_lastMoveY}    = -1;
	}
	if ($x == $self->{_lastMoveX} && $y == $self->{_lastMoveY}) {
		if (($now - $self->{_lastMoveTime}) < 2.0) {
			return;
		}
	}
	my $elapsed = $now - $self->{_lastMoveTime};
	if ($elapsed < 0.3) {
		return;
	}
	$self->{_lastMoveTime} = $now;
	$self->{_lastMoveX}    = $x;
	$self->{_lastMoveY}    = $y;
	my $coordString = pack('vv', int($y), int($x));
	my $encCoord = $self->_encryptWalkPayload($coordString);
	if (defined $encCoord) {
		my $hexPlain = join(' ', map { sprintf('%02X', ord($_)) } split(//, $coordString));
		my $hexEnc   = join(' ', map { sprintf('%02X', ord($_)) } split(//, $encCoord));
		$coordString = $encCoord;
	} else {
		message "[LANDVERSE] Walk NOT encrypted (service unavailable, will likely disconnect)\n", "sendPacket";
	}

	my $packet = $self->reconstruct({
		switch => 'character_move',
		coordString => $coordString,
	});
	my $hex = join(' ', map { sprintf('%02X', ord($_)) } split(//, $packet));
	$self->sendToServer($packet);
}

1;
