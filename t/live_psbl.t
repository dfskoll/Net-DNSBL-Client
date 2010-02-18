use Test::More;
use Test::Deep;
use Net::DNSBL::Client;

plan skip_all => 'DNS unavailable; skipping tests' unless Net::DNS::Resolver->new->query('cpan.org');
plan tests => 1;

my $c = Net::DNSBL::Client->new();

# http://psbl.surriel.com/
$c->query('127.0.0.2', [
	{
		domain => 'psbl.surriel.com',
		type   => 'match',
		data   => '127.0.0.2'
	},
	{
		domain => 'psbl.surriel.com',
		type   => 'match',
		data   => '127.0.0.9'
	},
]);

my @expected = ({
		domain     => 'psbl.surriel.com',
		userdata   => undef,
		hit        => 1,
		data       => '127.0.0.2',
		actual_hit => '127.0.0.2',
		type       => 'match'
	},
);

my $got = $c->get_answers();
cmp_deeply( $got, bag(@expected), "Got expected answers from psbl testpoint") || diag explain \@expected, $got;