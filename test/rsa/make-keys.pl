#!/usr/bin/perl

use 5.14.0;
use strict;
use warnings;
use Crypt::RSA;

my $rsa = new Crypt::RSA;

print "Identify (in 'name <email\@address>' format): ";
chomp(my $id = <STDIN>);
print "Password (or blank for unencrypted keys): ";
chomp(my $passwd = <STDIN>);

my @fields = (
	Identity  => $id,
	Size      => 1024,
	Verbosity => 1,
	Filename  => "rsa-key",
);
if (length $passwd) {
	push (@fields, Password => $passwd);
}

my ($public, $private) = $rsa->keygen (@fields);
