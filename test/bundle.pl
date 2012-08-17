#!/usr/bin/perl

use 5.14.0;
use strict;
use warnings;
use lib "../lib";
use Archive::Tyd;

my $tyd = Archive::Tyd->new (debug => 1);

open (my $test, ">", "test.tyd");
$tyd->{filename} = "test.tyd";

$tyd->save($test);
