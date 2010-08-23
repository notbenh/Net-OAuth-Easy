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
   trigger => \&set_net_oauth_protocol,
);
sub set_net_oauth_protocol { 
   $Net::OAuth::PROTOCOL_VERSION = (shift->protocol eq '1.0a') ? &Net::OAuth::PROTOCOL_VERSION_1_0A : &Net::OAuth::PROTOCOL_VERSION_1_0;
}

sub BUILD {
   my $self = shift;
   $self->set_net_oauth_protocol;
}

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
   coerce => 1,
   predicate => 'has_signature_key',
   clearer => 'clear_signature_key',
);

sub timestamp { time };
sub nonce { md5_hex( join '', rand(2**32), time, rand(2**32) ); };

has request_parameters => (
   is => 'rw',
   isa => 'HashRef[ArrayRef]',
   default => sub{{ request_token => [qw{consumer_key 
                                         consumer_secret 
                                         request_url 
                                         request_method 
                                         signature_key 
                                         signature_method 
                                         timestamp 
                                         nonce 
                                         callback 
                                         token
                                         token_secret
                                         verifier
                                        }],
                    access_token  => [qw{consumer_key 
                                         consumer_secret 
                                         request_url 
                                         request_method 
                                         signature_key 
                                         signature_method 
                                         timestamp 
                                         nonce 
                                         token
                                         token_secret
                                         verifier
                                        }],

                    protected_resource => [qw{
                                         consumer_key 
                                         consumer_secret 
                                         request_url 
                                         request_method 
                                         signature_key 
                                         signature_method 
                                         timestamp 
                                         nonce 
                                         token
                                         token_secret
                                         verifier
                                        }],
   }},
);

has exception_handle => (
   is => 'rw',
   isa => 'CodeRef',
   default => sub{sub{shift;die @_}},
);

sub build_request {
   my $self = shift;
   my $type = shift;
   my $request = Net::OAuth->request($type)->new($self->gather_request_parts($type => @_));

   $self->exception_handle->( q{Unable to sign request} )
      unless $request->sign;

   $self->exception_handle->( q{Unable to verify request} )
      unless $request->verify;

   return $request;
}

sub gather_request_parts {
   my $self = shift;
   my $type = shift;
   my %opts = @_;

   # use type to grab the right url
   my $url_method = sprintf q{%s_url}, $type;
   $opts{request_url} ||= $self->can($url_method) ? $self->$url_method : undef;

   # pull any overrides from %opts/@_ everything else is pulled from $self
   my %req  = map{ $_ => ( exists $opts{$_} ) ? delete $opts{$_} : ( $self->can($_) ) ? $self->$_ : undef;
                 } @{$self->request_parameters->{ $type } || [] };
   # TODO: this is likely not what we really want in cases where you pass Content, NOS builds the URL and then plucks from that, possibly more accurate?
   $req{extra_params} = \%opts if scalar(keys %opts); # save off anything left from @_ as extra params

   $req{protocol_version} = ($self->protocol eq '1.0a') ? &Net::OAuth::PROTOCOL_VERSION_1_0A : &Net::OAuth::PROTOCOL_VERSION_1_0 ;
   
   return %req;
}


has response => (
   is => 'rw',
   isa => 'Object', # TODO: this is too vague
   predicate => 'has_response',
   clearer => 'clear_response',
);
sub content {
   my $self = shift;
   ( $self->has_response ) ? $self->response->content : undef;
}

sub success {
   my $self = shift;
   return ( $self->has_response ) ? $self->response->is_success : 0;
}
sub failure { ! shift->success };
sub error{ 
   my $self = shift;
   return ($self->failure) ? join qq{\n}, map{$self->response->$_} qw{status_line content} : undef;
}

sub make_request {
   my $self = shift;
   my $content;
   # find content if it was passed
   for (my $i=0; $i<scalar(@_); $i++ ) {
      if (defined $_[$i] && $_[$i] =~ m/^Content$/i) {
         $content = delete $_[$i+1];
         delete $_[$i];
         last;
      }
   }
   $self->clear_response if $self->has_response;
   my $request = ( ref($_[0]) && $_[0]->isa('Net::OAuth::Message') ) ? $_[0] : $self->build_request(grep { defined }@_);

   my $req = HTTP::Request->new( $request->request_method => $request->to_url );
   $req->content($content) if defined $content;
   return $self->add_auth_headers($req, $request);
}

sub add_auth_headers {
   my ($self, $http_req, $oauth_req) = @_;
   $self->exception_handle( 'HTTP::Request expected as first paramater') unless $http_req->isa('HTTP::Request');
   $self->exception_handle( 'Net::OAuth::Message expected as second paramater') unless $oauth_req->isa('Net::OAuth::Message');
   $http_req->authorization( $oauth_req->to_authorization_header )
      if $self->request_method eq 'POST';
   return $http_req;
}

sub send_request {
   my $self = shift;
   my $req = ( ref($_[0]) && $_[0]->isa('HTTP::Request') ) ? $_[0] : $self->make_request(@_);
   $self->response( $self->ua->request( $req ) );
}

has $_ => (
   is => 'rw',
   isa => 'Str',
   predicate => qq{has_$_},
   clearer => qq{clear_$_},
) for qw{request_token request_token_secret access_token access_token_secret};

sub get_request_token {
   my $self = shift;
   $self->send_request(request_token => @_);
   if ($self->success) {
      my $resp = Net::OAuth->response('request token')->from_post_body($self->response->content);
      $self->request_token( $resp->token );
      $self->request_token_secret( $resp->token_secret );
   }
   return $self->success;
}
   
sub get_authorization_url {
   my $self = shift;
   my %opts = @_;
   $opts{oauth_token} ||= $self->request_token;
   $opts{callback}    ||= $self->callback;
   my $url  = URI->new( $self->authorize_token_url );
   $url->query_form( %opts );
   return $url;
}

sub process_authorization_callback {
   my $self = shift;
   my $url  = (ref($_[0]) eq '') ? URI->new($_[0]) : $_[0]; # if we are handed a string build a uri object of it
   my %opts = $url->query_form;
   for ( grep{! m/^oauth_/} keys %opts ) {
      delete $opts{$_};
   }
   return %opts;
}

has process_access_token_mapping => (
   is => 'rw',
   isa => 'HashRef[ArrayRef]',
   auto_deref => 1,
   default => sub{{ token        => [qw{oauth_token request_token}],
                    token_secret => [qw{request_token_secret}],
                    verifier     => [qw{oauth_verifier}],
                 }},
);

sub process_access_token_input {
   my $self = shift;
   my %opts = @_;
   my %mapp = $self->process_access_token_mapping;
   while ( my ( $key, $map ) = each %mapp ) {
      next if exists $opts{$key}; # dont overwrite anything that was passed to us (respect overwrites)
      for my $lookup ( @$map ) {
         my $value = ( exists $opts{$lookup} ) ? delete $opts{$lookup}
                   : ( $self->can($lookup)   ) ? $self->$lookup
                   :                             undef;  
         $opts{$key} = $value;
         next if $value; # stop looking if we found a value
      }
   }
   return %opts;
}

sub get_access_token {
   my $self = shift;
   my %opts = $self->process_access_token_input( (scalar(@_) == 1) 
                                                ? $self->process_authorization_callback(@_) 
                                                : @_
                                               );

   $self->send_request(access_token => %opts);
   if ($self->success) {
      my $resp = Net::OAuth->response('access token')->from_post_body($self->response->content);
      $self->access_token( $resp->token );
      $self->access_token_secret( $resp->token_secret );
   }
   return $self->success;
}

sub get_protected_resource {
   my $self = shift;
   my %opts = (scalar(@_) == 1) ? (request_url => $_[0]) : @_ ; # allow just the requested URL to be pased
   $opts{token} ||= $self->access_token;
   $opts{token_secret} ||= $self->access_token_secret;
   $self->send_request(protected_resource => %opts);
   return $self->success;
}




1;
