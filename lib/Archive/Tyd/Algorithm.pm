package Archive::Tyd::Algorithm;

use 5.14.0;
use strict;
use warnings;

our $VERSION = '1.00';

=head1 NAME

Archive::Tyd::Algorithm - Base class for file mangling algorithms.

=head1 SYNOPSIS

  package Archive::Tyd::Algorithm::Deflate;
  use base qw(Archive::Tyd::Algorithm);

=head1 DESCRIPTION

This is the base class for creating custom file mangling algorithms. These
algorithms are intended for compression or encryption of the individual files in
a Tyd archive.

=head1 METHODS

=head2 string name ()

This should return the name of the encryption algorithm, preferrably the fully
qualified package name (for ex. C<Archive::Tyd::Algorithm::Deflate>).

=head2 string provides ()

This should return a list of services provided by the algorithm. Currently the
following services are supported:

  encoding: The algorithm simply mangles data (this is useful for symmetric
            key encryption or compression algorithms).
  signing:  This algorithm supports signatures (for example RSA)
  pubkey:   This algorithm supports public key cryptography (for example RSA).

=head2 void init (args)

If your algorithm requires any initialization (for example, providing of an
encryption key) it should handle it in this method. C<args> is a list of
arguments provided by the user when they request this algorithm.

=head2 bin encode (bin file_contents)

Given the C<file_contents> as a scalar, encode it and return the encoded
version. This version should be the compressed or encrypted output.

=head2 bin decode (bin encoded)

Given the encoded data, decode it and return the original data.

=head2 bin sign (bin data)

Create a signature for the given data. This is only applicable to algorithms
that provide signing.

=head2 bool verify (big signature, bin data)

Verify the signature for the given data. This is only applicable to algorithms
that provide signing.

=head1 SEE ALSO

L<Archive::Tyd>

=cut

sub new {
	my $class = shift;
	$class    = ref($class) || $class;

	my $self = {};
	bless ($self, $class);

	# Call the init method.
	$self->init(@_);

	return $self;
}

# Internal use: querying methods.
sub can_sign {
	my $self = shift;
	return grep { /^signing$/ } $self->provides();
}

# You must override these!
sub init {}
sub provides { return (); }
sub encode { ... }
sub decode { ... }
sub sign { ... }
sub verify { ... }

1;
