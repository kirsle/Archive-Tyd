package Archive::Tyd::Checksum;

use 5.14.0;
use strict;
use warnings;

our $VERSION = '1.00';

=head1 NAME

Archive::Tyd::Checksum - Base class for checksum handlers.

=head1 SYNOPSIS

  package Archive::Tyd::Checksum::MyChecksum;
  use base qw(Archive::Tyd::Checksum);

=head1 DESCRIPTION

This is the base class for checksum handlers for L<Archive::Tyd>. Checksums are
used for verifying the integrity of a Tyd archive or for individual members of
the archive.

=head1 METHODS

You must override the following methods.

=head2 string name ()

This should return the algorithm's name, e.g. C<SHA1>.

=head2 string digest (filehandle)

This should take a file handle and return a checksum hash based on it.

=head2 bool verify (string hash, filehandle)

Verify that the given hash is the correct checksum for the file handle.

=head1 SEE ALSO

L<Archive::Tyd>

=cut

sub new {
	my $class = shift;
	$class    = ref($class) || $class;

	my $self = {};
	bless ($self, $class);
	return $self;
}

# You must override these!
sub name { ... }
sub digest { ... }
sub verify { ... }

1;
