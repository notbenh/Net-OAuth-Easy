package Net::OAuth::Easy;
use Moose;
use Digest::MD5 qw{md5_hex};
require Net::OAuth;
require HTTP::Request;

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
   default => sub{'1.0a'},
);

has $_ => (
   is => 'rw',
   isa => 'Str',
   predicate => qq{has_$_},
   clearer => qq{clear_$_},
) for qw{ consumer_key consumer_secret };

has $_ => (
   is => 'rw',
   isa => 'ValidURI', 
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
   isa => 'SignatureMethod',
   default => 'HMAC-SHA1',
);

has signature_key => (
   is => 'rw',
   isa => 'SignatureKey',
   predicate => 'has_signature_key',
   clearer => 'clear_signature_key',
);

sub timestamp { time };
sub nonce {
  md5_hex( join '', rand(2**32), time, rand(2**32) ); 
};

has request_parameters => (
   is => 'rw',
   isa => 'ArrayRef',
   auto_deref => 1,
   default => sub{[qw{ consumer_key 
                       consumer_secret 
                       request_url 
                       request_method 
                       signature_key 
                       signature_method 
                       timestamp 
                       nonce 
                       callback 
   }]},
);

sub build_generic_request {
   my $self = shift;
   my $type = shift;
   my %opts = @_;

   # use type to grab the right url
   my $url_method = sprintf q{%s_url}, $type;
   $opts{request_url} ||= $self->$url_method;

   # pull any overrides from %opts/@_ everything else is pulled from $self
   my %req  = map{ $_ => ( exists $opts{$_} ) ? delete $opts{$_} : $self->$_
                 } $self->request_parameters;
   $req{extra_params} = \%opts if scalar(keys %opts); # save off anything left from @_ as extra params

   $req{protocol_version} = ($self->protocol eq '1.0a') ? &Net::OAuth::PROTOCOL_VERSION_1_0A : &Net::OAuth::PROTOCOL_VERSION_1_0 ;

   my $request = Net::OAuth->request($type)->new(%req);

   die q{Unable to sign request} 
      unless $request->sign;

   die q{Unable to verify request}
      unless $request->verify;

   return $request;
}

has response => (
   is => 'rw',
   isa => 'Object', # TODO: this is too vague
   predicate => 'has_response',
   clearer => 'clear_response',
);

sub success {
   my $self = shift;
   return ( $self->has_response ) ? $self->response->is_success : 0;
}
sub failure { ! shift->success };

sub make_request {
   my $self    = shift;
   $self->clear_response if $self->has_response;
   my $request = ( ref($_[0]) && $_[0]->isa('Net::OAuth::Message') ) ? $_[0] : $self->build_generic_request(@_);

   my $req = HTTP::Request->new( $request->request_method => $request->to_url );
   $req->authorization( $request->to_authorization_header );
   
   $self->response( $self->ua->request( $req ) );
}
   


sub request_token {
   my $self = shift;
   
=pod
   o
       my $res = $ua->request(POST $request->to_url); # Post message to the Service Provider

    if ($res->is_success) {
        my $response = Net::OAuth->response('request token')->from_post_body($res->content);
        print "Got Request Token ", $response->token, "\n";
        print "Got Request Token Secret ", $response->token_secret, "\n";
    }
    else {
        die "Something went wrong";
    }
=cut

}




1;
