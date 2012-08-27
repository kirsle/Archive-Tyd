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
if (!-f "package-signed.tyd") {
	die "No package-signed.tyd. Run create-signed.pl first.";
}

print "Loading keys from disk\n";
my $pubkey = Crypt::RSA::Key::Public->new (
	Filename => "rsa-key.public",
);

print "Creating Archive::Tyd object.\n";
my $tyd = Archive::Tyd->new("package-signed.tyd", debug => 1) or die "Loading error!";

# Using RSA for signing.
$tyd->algorithm("RSA", {
	pubkey  => $pubkey,
});

# Verify the signature.
print "Verifying the signature...\n";
my $ok = $tyd->verify();
if (!$ok) {
	print "Verification failure! " . $tyd->error() . "\n";
}
if ($ok) {
	print "Signature matches!\n";
}
