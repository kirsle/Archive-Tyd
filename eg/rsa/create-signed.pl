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

print "If the private key is encrypted, enter the password: ";
chomp(my $password = <STDIN>);

print "Loading keys from disk\n";
my $privkey = Crypt::RSA::Key::Private->new (
	Filename => "rsa-key.private",
	Password => length $password ? $password : undef,
);

print "Creating Archive::Tyd object.\n";
my $tyd = Archive::Tyd->new(debug => 1);

# Using RSA for signing.
$tyd->algorithm("RSA", {
	privkey => $privkey,
});

# Add some files.
$tyd->add_file("../source/file1.txt" => "/file1.txt");
$tyd->add_file("../source/file2.png" => "/file2.png");
$tyd->add_file("../source/file3.txt" => "/file3.txt");

# Write, with signature.
$tyd->save("package-signed.tyd", signature => 1);
