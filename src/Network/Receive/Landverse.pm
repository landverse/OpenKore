package Network::Receive::Landverse;
use strict;
use base qw(Network::Receive::kRO::RagexeRE_2021_11_03);
use Globals qw($char $messageSender %config);
use I18N qw(bytesToString);
use Log qw(debug message);

sub new {
	my ( $class ) = @_;
	my $self = $class->SUPER::new( @_ );

	# The real client normally gets 0x0AC4 (encrypted response from account server).
	# In plaintext mode the server may respond with 0x0C32 instead.
	# Register both so we can handle whichever the server sends.
	my %packets = (
		'0C32' => ['account_server_info', 'v a4 a4 a4 a4 a26 C x17 a*', [qw(len sessionID accountID sessionID2 lastLoginIP lastLoginTime accountSex serverInfo)]],
		'0AC4' => ['account_server_info', 'v a4 a4 a4 a4 a26 C x17 a*', [qw(len sessionID accountID sessionID2 lastLoginIP lastLoginTime accountSex serverInfo)]],
	);

	$self->{packet_list}{$_} = $packets{$_} for keys %packets;

	# Default to 0x0AC4 (what the real server sends), but allow fallback to 0x0C32
	my %handlers = qw(
		account_server_info 0AC4
	);

	$self->{packet_lut}{$_} = $handlers{$_} for keys %handlers;

	return $self;
}

# Override to handle potentially encrypted 0x0AC4 response
sub account_server_info {
	my ($self, $args) = @_;

	my $switch = sprintf("%04X", unpack("v", pack("v", hex($args->{switch} || '0AC4'))));
	message "[LANDVERSE] Received account_server_info ($switch), len=" . length($args->{RAW_MSG}) . " bytes\n", "connection";

	# If the response looks encrypted (all high-entropy bytes), try decrypting
	if ($config{landverseEncrypt} && $args->{switch} eq '0AC4') {
		my $raw = $args->{RAW_MSG};
		my $payload = substr($raw, 4);  # skip 2-byte pktId + 2-byte len
		my $plen = length($payload);

		# Check if payload length is multiple of 32 (Rijndael block size)
		if ($plen > 0 && ($plen % 32) == 0) {
			message "[LANDVERSE] Attempting Rijndael decryption of 0x0AC4 ($plen bytes payload)\n", "connection";
			eval {
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
				my $decrypted = $rijndael->Decrypt($payload, undef, $plen, 0);

				my $hex = join(' ', map { sprintf("%02X", ord($_)) } split(//, substr($decrypted, 0, 40)));
				message "[LANDVERSE] Decrypted first 40 bytes: [$hex]\n", "connection";
			};
			if ($@) {
				message "[LANDVERSE] Decryption error: $@\n", "connection";
			}
		} else {
			message "[LANDVERSE] Payload length $plen is NOT a multiple of 32, skipping decryption\n", "connection";
		}
	}

	# Dump first bytes for debugging
	my $hexFirst = join(' ', map { sprintf("%02X", ord($_)) } split(//, substr($args->{RAW_MSG}, 0, 40)));
	debug "[LANDVERSE] account_server_info raw first 40: [$hexFirst]\n", "connection", 2;

	# Let parent handle the parsed data
	$self->SUPER::account_server_info($args);
}

1;
