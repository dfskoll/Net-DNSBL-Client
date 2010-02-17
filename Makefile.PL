use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::DNSBL::Client',
    AUTHOR              => q{David F. Skoll <dfs@roaringpenguin.com>},
    VERSION_FROM        => 'lib/Net/DNSBL/Client.pm',
    ABSTRACT_FROM       => 'lib/Net/DNSBL/Client.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'restrictive')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-DNSBL-Client-*' },
);
