use strict;
use warnings;
use inc::Module::Install;

name	 'Net-DNSBL-Client';
all_from 'lib/Net/DNSBL/Client.pm';

requires 'Net::DNS::Resolver';
requires 'IO::Socket';

build_requires 'Test::More';
build_requires 'Test::Deep';
build_requires 'Test::Exception';
install_script 'script/dnsblcheck';

WriteAll;
