use strict;
use warnings;
use Module::Build;

my $class = Module::Build->subclass(
    class => 'My::Builder',
    code => q{
        sub ACTION_docs {
            use Pod::Select;
            
            my $self = shift;
            
            podselect({ -output => 'README.pod' },
                'lib/Dancer/Plugin/Auth/Basic.pm');
            
            return $self->SUPER::ACTION_docs;
        }
    }
);

my $builder = $class->new(
    module_name         => 'Dancer::Plugin::Auth::Basic',
    license             => 'perl',
    dist_author         => q{Michal Wojciechowski <odyniec@cpan.org>},
    dist_version_from   => 'lib/Dancer/Plugin/Auth/Basic.pm',
    requires => {
        'Dancer' => 1.3070,
        'HTTP::Headers' => 0,
    },
    build_requires => {
        'Pod::Select' => 0,
        'Test::More' => 0,
    },
    add_to_cleanup      => [ 'Dancer-Plugin-Auth-Basic-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();
