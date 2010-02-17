package Net::DNSBL::Client;
use strict;
use warnings;

use Carp;
use Net::DNS::Resolver;
use IO::Select;

sub new
{
	my ($class, $args) = @_;
	my $self = {
		resolver => undef,
		timeout  => 10,
	};
	foreach my $possible_arg (keys(%$self)) {
		my $val = delete $args->{$possible_arg};
		$self->{$possible_arg} = $val if defined($val);
	}
	if (scalar(%$args)) {
		croak("Unknown arguments to new: " .
		      join(', ', (sort { $a cmp $b } keys(%$args))));
	}
	$self->{resolver} = Net::DNS::Resolver->new() unless $self->{resolver};
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

sub query
{
	my ($self, $ipaddr, $options, $dnsbls) = @_;

	my $early_exit = 0;
	$early_exit = 1 if ($options && $options->{early_exit});

	# Reverse the IP address in preparation for lookups
	my $revip = $self->reverse_address($ipaddr);

	# Build a hash of domains to query.  The key is the domain;
	# value is an arrayref of type/data pairs
	my $domains = $self->_build_domains($dnsbls);

}

sub _build_domains
{
	my($self, $dnsbls) = @_;
	my $domains = {};

	foreach my $entry (@$dnsbls) {
		my $domain = $entry->{domain};
		my $type = $entry->{type} || 'normal';
		my $data = $entry->{data};
		push(@{$domains->{$domain}}, {type => $type,
					      data => $data});
	}
	return $domains;
}

sub _do_queries
{
	my ($self, $revip, $domains) = @;

	my %sock_to_domain;

	my $res = $self->{resolver};
	my $sel = IO::Select->new();
	my $sock;

	foreach my $domain (keys(%$domains)) {
		$sock = $res->bgsend("$revip.$domain", 'A');
		$sock_to_domain{$sock} = $domain;
		$sel->add($sock);
	}

	my $ans = [];

	my @ready;
	while($sel->count()) {
		@ready = $sel->can_read();

		# This should never happen, but just in case...
		return $ans unless scalar(@ready);

		foreach $sock (@ready) {
			my $pack = $res->bgread($sock);
			my $domain = $sock_to_domain{$sock};
			$sel->remove($sock);
			undef($sock);
			next if ($pack->header->rcode eq 'SERVFAIL' ||
				 $pack->header->rcode eq 'NXDOMAIN');
			$self->_process_reply($domain, $pack, $domains, $ans);
		}

	}
	return $ans;
}

1;
