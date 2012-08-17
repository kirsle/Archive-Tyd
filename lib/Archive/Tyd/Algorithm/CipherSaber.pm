package Archive::Tyd::Algorithm::CipherSaber;

# Provides the CipherSaber encryption algorithm for Archive::Tyd.

use 5.14.0;
use strict;
use warnings;
use Crypt::CipherSaber;
use base qw(Archive::Tyd::Algorithm);

our $VERSION = "1.00";

sub name {
	return __PACKAGE__;
}

sub init {
	my ($self, @args) = @_;

	# The password must be provided.
	my $password = shift(@args);
	if (!defined $password) {
		# None provided, ask on standard input.
		print "Password> ";
		chomp($password = <STDIN>);
		if (!defined $password || !length $password) {
			die "Password is required.";
		}
	}

	# Create the cipher.
	$self->{cs} = Crypt::CipherSaber->new($password);
}

sub encode {
	my ($self, $data) = @_;
	return $self->{cs}->encrypt($data);
}

sub decode {
	my ($self, $data) = @_;
	return $self->{cs}->decrypt($data);
}

1;
