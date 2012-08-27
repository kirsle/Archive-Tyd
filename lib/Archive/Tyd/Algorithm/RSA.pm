package Archive::Tyd::Algorithm::RSA;

# Provides the RSA encryption algorithm for Archive::Tyd.

use 5.14.0;
use strict;
use warnings;
use Crypt::RSA;
use base qw(Archive::Tyd::Algorithm);

our $VERSION = "1.00";

sub name {
	return __PACKAGE__;
}

sub provides {
	return ("encoding", "signing");
}

sub init {
	my ($self, $args) = @_;

	# What are we doing? Signing, or encrypting?
	my $pubkey  = delete $args->{pubkey} || undef;
	my $privkey = delete $args->{privkey} || undef;

	# Store the keys.
	$self->{keys} = {
		public  => $pubkey,
		private => $privkey,
	};

	# Make an RSA object.
	$self->{rsa} = Crypt::RSA->new();
}

sub sign {
	my ($self, $data) = @_;

	# We need a private key for this.
	if (!defined $self->{keys}->{private}) {
		die "Private key is required for RSA signature creation!";
	}

	# Make the signature.
	my $signature = $self->{rsa}->sign (
		Message => $data,
		Key     => $self->{keys}->{private},
	);

	return $signature;
}

sub verify {
	my ($self, $signature, $data) = @_;

	# We need the public key for this.
	if (!defined $self->{keys}->{public}) {
		die "Public key is required for RSA signature verification!";
	}

	# Verify.
	return $self->{rsa}->verify (
		Message   => $data,
		Signature => $signature,
		Key       => $self->{keys}->{public},
	);
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
