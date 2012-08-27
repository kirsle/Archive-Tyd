#!/usr/bin/perl

use 5.14.0;
use strict;
use warnings;
use lib "../../lib";
use Archive::Tyd;
use Crypt::RSA;

# We need keys.
if (!-f "rsa-key.public" || !-f "rsa-key.private") {
	die "No RSA keys found. Run make-keys.pl first.";
}
if (!-f "package-crypted.tyd") {
	die "No package-crypted.tyd. Run create-crypted.pl first.";
}

print "If the private key is encrypted, enter the password: ";
chomp(my $password = <STDIN>);

print "Loading keys from disk\n";
my $privkey = Crypt::RSA::Key::Private->new (
	Filename => "rsa-key.private",
);

print "Creating Archive::Tyd object.\n";
my $tyd = Archive::Tyd->new("package-crypted.tyd",
	debug => 1,
	algorithm => ["RSA", { privkey => $privkey } ]
);

# Extract.
$tyd->extract();
