use Test::More tests => 1;
use Test::Deep;
use Net::DNSBL::Client;

my $c = Net::DNSBL::Client->new();


$c->query('127.0.0.2',
	undef,
	[ {
		domain => 'zen.spamhaus.org',
		type   => 'match',
		data   => '127.0.0.2'
	},
	{
		domain => 'zen.spamhaus.org',
		type   => 'match',
		data   => '127.0.0.4'
	},
	{
		domain => 'zen.spamhaus.org',
		type   => 'match',
		data   => '127.0.0.10'
	},
	{
		domain => 'zen.spamhaus.org',
		type   => 'match',
		data   => '127.0.0.20'
	}
]);

my @expected = (
          {
            'domain' => 'zen.spamhaus.org',
            'userdata' => undef,
            'hit' => 1,
            'data' => '127.0.0.2',
            'type' => 'match'
          },
          {
            'domain' => 'zen.spamhaus.org',
            'userdata' => undef,
            'hit' => 1,
            'data' => '127.0.0.4',
            'type' => 'match'
          },
          {
            'domain' => 'zen.spamhaus.org',
            'userdata' => undef,
            'hit' => 1,
            'data' => '127.0.0.10',
            'type' => 'match'
          }
);

my $got = $c->get_answers();
cmp_deeply( $got, bag(@expected), "Got expected answers from spamhaus testpoint");
