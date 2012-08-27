#!/usr/bin/perl

use 5.14.0;
use strict;
use warnings;
use lib "../lib";
use Archive::Tyd;

my $tyd = Archive::Tyd->new ("test.tyd", debug => 1);
