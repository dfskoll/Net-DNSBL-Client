package Net::DNSBL::Client;
use strict;
use warnings;

use Carp;
use Net::DNS::Resolver;
use IO::Select;

our $VERSION = '0.100';

sub new
{
	my ($class, $args) = @_;
	my $self = {
		resolver   => undef,
		timeout    => 10,
		early_exit => 0,
	};
	foreach my $possible_arg (keys(%$self)) {
		if( exists $args->{$possible_arg} ) {
			$self->{$possible_arg} = delete $args->{$possible_arg};
		}
	}
	if (scalar(%$args)) {
		croak("Unknown arguments to new: " .
		      join(', ', (sort { $a cmp $b } keys(%$args))));
	}
	$self->{resolver} = Net::DNS::Resolver->new() unless $self->{resolver};

	$self->{in_flight} = 0;
	bless $self, $class;
	return $self;
}

sub get_resolver
{
	my ($self) = @_;
	return $self->{resolver};
}

sub get_timeout
{
	my ($self) = @_;
	return $self->{timeout};
}

sub set_timeout
{
	my ($self, $secs) = @_;
	$self->{timeout} = $secs;
	return $secs;
}

sub query_is_in_flight
{
	my ($self) = @_;
	return $self->{in_flight};
}

sub query
{
	my ($self, $ipaddr, $options, $dnsbls) = @_;

	croak("Cannot issue a query while one is in flight")
	    if $self->{in_flight};

	if ($options && $options->{early_exit}) {
		$self->{early_exit} = 1;
	}

	# Reverse the IP address in preparation for lookups
	my $revip = $self->reverse_address($ipaddr);

	# Build a hash of domains to query.  The key is the domain;
	# value is an arrayref of type/data pairs
	$self->{domains} = $self->_build_domains($dnsbls);
	$self->_send_queries($revip);
}

sub get_answers
{
	my ($self) = @_;
	croak("Cannot call get_answers unless a query is in flight")
	    unless $self->{in_flight};

	my $ans = $self->_collect_results();
	$self->{in_flight} = 0;
	delete $self->{sel};
	delete $self->{sock_to_domain};
	delete $self->{domains};

	return $ans;
}

sub _build_domains
{
	my($self, $dnsbls) = @_;
	my $domains = {};

	foreach my $entry (@$dnsbls) {
		push(@{$domains->{$entry->{domain}}}, {
			domain   => $entry->{domain},
			type     => ($entry->{type} || 'normal'),
			data     => $entry->{data},
			userdata => $entry->{userdata},
			hit      => 0
		});
	}
	return $domains;
}

sub _send_queries
{
	my ($self, $revip) = @_;

	$self->{in_flight} = 1;
	$self->{sel} = IO::Select->new();
	$self->{sock_to_domain} = {};

	foreach my $domain (keys(%{$self->{domains}})) {
		my $sock = $self->{resolver}->bgsend("$revip.$domain", 'A');
		$self->{sock_to_domain}->{$sock} = $domain;
		$self->{sel}->add($sock);
	}
}

sub _collect_results
{
	my ($self) = @_;
	my $ans = [];

	my $terminate = time() + $self->{timeout};
	my $sel = $self->{sel};

	while(time() <= $terminate && $sel->count()) {
		my $expire = $terminate - time();
		$expire = 1 if ($expire < 1);
		my @ready = $sel->can_read($expire);

		return $ans unless scalar(@ready);

		foreach my $sock (@ready) {
			my $pack = $self->{resolver}->bgread($sock);
			my $domain = $self->{sock_to_domain}{$sock};
			$sel->remove($sock);
			undef($sock);
			next if ($pack->header->rcode eq 'SERVFAIL' ||
				 $pack->header->rcode eq 'NXDOMAIN');
			$self->_process_reply($domain, $pack, $ans);
		}
		return $ans if ($self->{early_exit} && (scalar(@$ans) > 0));

	}
	return $ans;
}

sub _process_reply
{
	my ($self, $domain, $pack, $ans) = @_;

	my $entry = $self->{domains}->{$domain};

	foreach my $rr ($pack->answer) {
		next unless $rr->type eq 'A';
		foreach my $dnsbl (@$entry) {
			next if $dnsbl->{hit};
			if ($dnsbl->{type} eq 'normal') {
				$dnsbl->{hit} = 1;
				push(@$ans, $dnsbl);
			} elsif ($dnsbl->{type} eq 'match') {
				next unless $rr->address eq $dnsbl->{data};
				$dnsbl->{hit} = 1;
				push(@$ans, $dnsbl);
			} elsif ($dnsbl->{type} eq 'mask') {
				my ($a, $b, $c, $d);

				# For mask, we can be given an IP mask like
				# a.b.c.d, or an integer n.  The latter case
				# is treated as 0.0.0.n.
				if ($dnsbl->{data} =~ /^\d+$/) {
					$a = 0;
					$b = 0;
					$c = 0;
					$d = $dnsbl->{data};
				} else {
					($a, $b, $c, $d) = split(/\./, $dnsbl->{data});
				}

				my ($aa, $bb, $cc, $dd) = split(/\./, $rr->address);
				next unless ($a & $aa) || ($b & $bb) || ($c & $cc) || ($d & $dd);
				$dnsbl->{hit} = 1;
				push(@$ans, $dnsbl);
			}
		}
	}
}

sub reverse_address
{
	my ($self, $addr) = @_;

	# The following regex handles both regular IPv4 addresses
	# and IPv6-mapped IPV4 addresses (::ffff:a.b.c.d)
	if ($addr =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) {
		return "$4.$3.$2.$1";
	}
	if ($addr =~ /:/) {
		$addr = $self->expand_ipv6_address($addr);
		$addr =~ s/://g;
		return join('.', reverse(split(//, $addr)));
	}

	croak("Unrecognized IP address $addr");
}

sub expand_ipv6_address
{
	my ($self, $addr) = @_;

	return '0000:0000:0000:0000:0000:0000:0000:0000' if ($addr eq '::');
	if ($addr =~ /::/) {
		# Do nothing if more than one pair of colons
		return $addr if ($addr =~ /::.*::/);

		# Make sure we don't begin or end with ::
		$addr = "0000$addr" if $addr =~ /^::/;
		$addr .= '0000' if $addr =~ /::$/;

		# Count number of colons
		my $colons = ($addr =~ tr/:/:/);
		if ($colons < 8) {
			my $missing = ':' . ('0000:' x (8 - $colons));
			$addr =~ s/::/$missing/;
		}
	}

	# Pad short fields
	return join(':', map { (length($_) < 4 ? ('0' x (4-length($_)) . $_) : $_) } (split(/:/, $addr)));
}

#my $c = Net::DNSBL::Client->new();
#$c->query('127.0.0.2', undef,
#	  [{domain => 'zen.spamhaus.org',
#	    type => 'match',
#	    data => '127.0.0.2'},
#	   {domain => 'zen.spamhaus.org',
#	    type => 'match',
#	    data => '127.0.0.4'},
#	   {domain => 'zen.spamhaus.org',
#	    type => 'match',
#	    data => '127.0.0.10'},
#	   {domain => 'zen.spamhaus.org',
#	    type => 'match',
#	    data => '127.0.0.20'}]);

#my $ans = $c->get_answers();

#use Data::Dumper;
#print Dumper($ans);

1;