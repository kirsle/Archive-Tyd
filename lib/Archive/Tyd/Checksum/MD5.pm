package Archive::Tyd::Checksum::MD5;

# Provides an MD5 method for Archive::Tyd checksumming.

use 5.14.0;
use strict;
use warnings;
use Digest::MD5;
use base qw(Archive::Tyd::Checksum);

our $VERSION = "1.00";

sub name () { "MD5" }

sub digest {
	my ($self, $fh) = @_;

	my $ctx = Digest::MD5->new;
	if (ref($fh)) {
		$ctx->addfile($fh);
	} else {
		$ctx->add($fh);
	}
	return $ctx->hexdigest;
}

sub verify {
	my ($self, $hash, $fh) = @_;

	my $digest = $self->digest($fh);
	return $digest eq $hash;
}

1;
