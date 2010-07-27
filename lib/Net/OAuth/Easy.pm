package Net::OAuth::Easy;
use Moose;
require Net::OAuth;

# ABSTRACT: A moose class that abstracts Net::OAuth for you

with qw{
   Net::OAuth::Easy::Roles::Types
};

has ua => (
   is => 'rw',
   isa => 'LWP::UserAgent',
   lazy => 1,
   default => sub{
      require LWP::UserAgent;
      LWP::UserAgent->new;
   },
);

has protocol => (
   is => 'rw',
   isa => 'OAuthProtocol',
   lazy => 1,
   default => '1.0a',
);

has $_ => (
   is => 'rw',
   isa => 'Str',
   predicate => qq{has_$_},
   clearer => qq{clear_$_},
) for qw{ consumer_key consumer_secret };

has $_ => (
   is => 'rw',
   isa => 'URI', 
   predicate => qq{has_$_},
   clearer => qq{clear_$_},
) for qw{ request_token_url authorize_token_url access_token_url callback };

has request_method => (
   is => 'rw',
   isa => 'RequestMethod',
   default => 'GET',
);

has signature_method => (
   is => 'rw',
   isa => 'RequestMethod',
   default => 'GET',
);

has signature_key => (
   is => 'rw',
   isa => 'SignatureKey',
   predicate => 'has_signature_key',
   clearer => 'clear_signature_key',
);

sub timestamp { time };
sub nonce {
  join '', rand(2**32), time, rand(2**32); 
};

has request_parameters => (
   is => 'rw',
   isa => 'ArrayRef',
   auto_deref => 1,
   default => sub{[qw{ consumer_key 
                       consumer_secret 
                       request_url 
                       request_method 
                       signature_method 
                       timestamp 
                       nonce 
                       callback 
   }]},
);

sub generic_request {
   my $self = shift;
   my $type = shift;
   my %opts = @_;

   # use type to grab the right url
   my $url_method = sprintf q{%s_url}, $type;
   $opts{request_url} ||= $self->$url_method;

   # pull any overrides from %opts/@_ everything else is pulled from $self
   my %req  = map{ $_ => ( exists $opts{$_} ) ? delete $opts{$_} : $self->$_ } $self->request_parameters;
   $req{extra_params} = \%opts if scalar(keys %opts); # save off anything left from @_ as extra params

   my $request = Net::OAuth->request($type)->new(%req);
   $request->sign;
   return $request;
}


sub request_token {
   my $self = shift;
}




1;
