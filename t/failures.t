use Test::More tests => 4;
use Test::Exception;
use Net::DNSBL::Client;

my $c = Net::DNSBL::Client->new();

throws_ok
	{ $c->query(); }
	qr/^First argument \(ip address\) is required/,
	'->query dies when called with no args';

throws_ok
	{ $c->query('127.0.0.2') }
	qr/^Second argument \(dnsbl list\) is required/,
	'->query() dies when called with no dnsbl list';

throws_ok
	{ $c->query('roaringpenguin.com', [ { domain => 'bogus.for.testing' } ] ) }
	qr/^Unrecognized IP address 'roaringpenguin.com'/,
	'->query() dies when called with hostname instead of IP address';

# Hack
{
	local $c->{in_flight} = 1;
	throws_ok
		{ $c->query('127.0.0.2', [ { domain => 'bogus.for.testing' } ] ) }
		qr/^Cannot issue new query while one is in flight/,
		'->query() dies when called with existing query in flight';
}
