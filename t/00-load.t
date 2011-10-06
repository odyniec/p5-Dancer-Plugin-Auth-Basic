#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Dancer::Plugin::Auth::Basic' ) || print "Bail out!
";
}

diag( "Testing Dancer::Plugin::Auth::Basic $Dancer::Plugin::Auth::Basic::VERSION, Perl $], $^X" );
