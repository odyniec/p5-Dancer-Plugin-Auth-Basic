package Dancer::Plugin::Auth::Basic;

=head1 NAME

Dancer::Plugin::Auth::Basic - Basic HTTP authentication for Dancer web apps

=cut

use warnings;
use strict;

use Dancer ':syntax';
use Dancer::Plugin;
use Dancer::Response;
use HTTP::Headers;
use MIME::Base64;

our $VERSION = '0.01';

my $settings = plugin_setting;

# Protected paths defined in the configuration
my $paths = {};
# "Global" users
my $users = {};

if (exists $settings->{paths}) {
    $paths = $settings->{paths};
}

if (exists $settings->{users}) {
    $users = $settings->{users};
}

sub _auth_basic {
    my (%options) = @_;
    
    # Get authentication data from request
    my $auth = request->env->{HTTP_AUTHORIZATION};
    
    if (defined $auth && $auth =~ /^Basic (.*)$/) {
        my ($user, $password) = split(/:/, (MIME::Base64::decode($1) || ":"));
        
        if (exists $options{user}) {
            # A single user is defined
            if ($user eq $options{user} && $password eq $options{password}) {
                # Authorization succeeded
                return 1;
            }
        }
        elsif (exists $options{users}) {
            # Multiple users are defined
            if ($password eq $options{users}->{$user}) {
                # Authorization succeeded
                return 1;
            }
        }
        elsif (defined $users) {
            # Use the "global" users list
            if ($password eq $users->{$user}) {
                # Authorization succeeded
                return 1;
            }
        }
        else {
            # No users defined? NONE SHALL PASS!
            warning __PACKAGE__ . ": No user/password defined";
        }
    }
    
    my $content = "Authorization required";
    
    return halt(Dancer::Response->new(
        status => 401,
        content => $content,
        headers => [
            'Content-Type' => 'text/plain',
            'Content-Length' => length($content),
            'WWW-Authenticate' => 'Basic realm="' . ($options{realm} ||
                "Restricted area") . '"'
        ]
    ));
}

before sub {
    # Check if the request matches one of the protected paths
    foreach my $path (keys %$paths) {
        my $path_re = '^' . quotemeta($path);
        
        if (request->path_info =~ qr{$path_re}) {
            _auth_basic %{$paths->{$path}};
            last;
        }
    }
};

register auth_basic => \&_auth_basic;

register_plugin;

1; # End of Dancer::Plugin::Auth::Basic
__END__

=pod

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

Dancer::Plugin::Auth::Basic provides basic HTTP authentication for Dancer web
applications.

Add the plugin to your application:

    use Dancer::Plugin::Auth::Basic;

Configure the protected paths and users/passwords in the YAML configuration
file:

    plugins:
      "Auth::Basic":
        paths:
          "/restricted":
            realm: Restricted zone
            user: alice
            password: AlicesPassword
          "/secret/data":
            users:
              alice: AlicesPassword
              bob: BobsPassword

You can also call the C<auth_basic> function in a before filter:

    before sub {
        auth_basic user => 'alice', password => 'AlicesPassword';
    };

or in a route handler:
    
    get '/confidential' => sub {
        auth_basic realm => 'Authorized personnel only',
            users => { 'alice' => 'AlicesPassword', 'bob' => 'BobsPassword' };
        
        # Authenticated
        ...
    };

=head1 DESCRIPTION

Dancer::Plugin::Auth::Basic adds basic HTTP authentication to Dancer web
applications.

=head1 CONFIGURATION

The available configuration options are listed below.

=head2 paths

Defines one or more paths that will be protected, including sub-paths
(so if the path is C<"/restricted">, then C<"/restricted/secret/file.html"> will
also be protected). Each path can have the following parameters:

=over 4

=item * C<realm>

Realm name that will be displayed in the authentication dialog. Default:
C<"Restricted area">

=item * C<password>

Password (if a single user is allowed access).

=item * C<user>

User name (if a single user is allowed access).

=item * C<users>

A list of user names and passwords (if multiple users are allowed access).

=back

Example:

    plugins:
      "Auth::Basic":
        paths:
          "/secret":
            realm: "Top secret documents"
            user: charlie
            password: CharliesPassword
          "/documents":
            realm: "Only for Bob and Tim"
            users:
              bob: BobsPassword
              tim: TimsPassword

=head1 FUNCTIONS

=head2 auth_basic

This function may be called in a before filter or at the beginning of a route
handler. It checks if the client is authorized to access the requested path --
if not, it immediately returns a 401 Unauthorized response to prompt the user to
authenticate.

    auth_basic realm => 'Top secret', user => 'alice',
        password => 'AlicesPassword';

Parameters:

=over 4

=item * C<realm>

Realm name that will be displayed in the authentication dialog. Default:
C<"Restricted area">

=item * C<password>

Password (if a single user is allowed access).

=item * C<user>

User name (if a single user is allowed access).

=item * C<users>

A hash reference mapping user names to passwords (if multiple users are allowed
access).

=back

=head1 AUTHOR

Michal Wojciechowski, C<< <odyniec at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-dancer-plugin-auth-basic at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Dancer-Plugin-Auth-Basic>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Dancer::Plugin::Auth::Basic


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Dancer-Plugin-Auth-Basic>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Dancer-Plugin-Auth-Basic>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Dancer-Plugin-Auth-Basic>

=item * Search CPAN

L<http://search.cpan.org/dist/Dancer-Plugin-Auth-Basic/>

=back


=head1 ACKNOWLEDGEMENTS

Inspired by Tatsuhiko Miyagawa's L<Plack::Middleware::Auth::Basic>.


=head1 LICENSE AND COPYRIGHT

Copyright 2011 Michal Wojciechowski.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

