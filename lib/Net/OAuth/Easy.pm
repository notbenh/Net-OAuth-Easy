package Net::OAuth::Easy;
use Moose;
use Digest::MD5 qw{md5_hex};
require Net::OAuth;
require HTTP::Request;

# ABSTRACT: A moose class that abstracts Net::OAuth for you

=head1 SYNOPSIS

  use Net::OAuth::Easy;
  my $oauth = Net::OAuth::Easy->new( 
      consumer_key        => $key,
      consumer_secret     => $secret,
      request_token_url   => q{http://someplace.com/request_token},
      authorize_token_url => q{http://someplace.com/authorize},
      access_token_url    => q{http://someplace.com/access_token},
      callback            => q{http://here.com/user},
  );
  $oauth->get_request_token;
  # save off request token secret somewhere, you need it later
  $some_session_idea->request_token_secret($oauth->requset_token_secret);

  my $auth_url   = $oauth->get_authorization_url;
  # redirect user to $auth_url

  ...

  #reload the token secret
  $oauth->request_token_secret( $some_session_idea->request_token_secret );
  $oauth->get_access_token( $q->url );
  #safe off the access tokens now
  $some_storage_idea->access_token($oauth->access_token);
  $some_storage_idea->access_token_secret($oauth->access_token_secret);

  ...

  $oauth->access_token( $some_storage_idea->access_token );
  $oauth->access_token_secret( $some_storage_idea->access_token_secret );
  $oauth->get_protected_resource( $restricted_url )
  

get_access_token


=head1 DESCRIPTION

=head1 OVERVIEW

=roles Net::OAuth::Easy::Roles::Types

=cut

with qw{
   Net::OAuth::Easy::Roles::Types
};

=attr ua

A LWP::UserAgent object to do the message passing. 

=cut

has ua => (
   is => 'rw',
   isa => 'LWP::UserAgent',
   lazy => 1,
   default => sub{
      require LWP::UserAgent;
      LWP::UserAgent->new;
   },
);

=attr protocol

What OAuth protocol do you wish your messages to be build in? 

=over 4

=item * '1.0a' B<Default>

=item * '1.0'

=back

=cut

has protocol => (
   is => 'rw',
   isa => 'OAuthProtocol',
   lazy => 1,
   default => sub{'1.0a'},
   trigger => \&set_net_oauth_protocol,
);
sub set_net_oauth_protocol { 
   no warnings;
   $Net::OAuth::PROTOCOL_VERSION = (shift->protocol eq '1.0a') ? &Net::OAuth::PROTOCOL_VERSION_1_0A : &Net::OAuth::PROTOCOL_VERSION_1_0;
}

sub BUILD {
   my $self = shift;
   $self->set_net_oauth_protocol;
}

=attr consumer_key

=method has_consumer_key

=method clear_consumer_key

=attr consumer_secret

=method has_consumer_secret

=method clear_consumer_secret

=cut

has $_ => (
   is => 'rw',
   isa => 'Str',
   predicate => qq{has_$_},
   clearer => qq{clear_$_},
) for qw{ consumer_key consumer_secret };

=attr request_token_url

=method has_request_token_url

=method clear_request_token_url

=attr authorize_token_url

=method has_authorize_token_url

=method clear_authorize_token_url

=attr access_token_url

=method has_access_token_url

=method clear_access_token_url

=attr callback

=method has_callback

=method clear_callback

=cut

has $_ => (
   is => 'rw',
   isa => 'ValidURI', 
   predicate => qq{has_$_},
   clearer => qq{clear_$_},
) for qw{ request_token_url authorize_token_url access_token_url callback };

=attr request_method

Defines the method of the request.

=over 4

=item * 'GET' B<Default>

=item * 'POST'

=back 

=cut

has request_method => (
   is => 'rw',
   isa => 'RequestMethod',
   default => 'GET',
);

=attr signature_method

Defines the method to sign the request.

=over 4

=item * 'HMAC-SHA1' B<Default>

=item * 'RSA-SHA1'

=back

=cut

has signature_method => (
   is => 'rw',
   isa => 'SignatureMethod',
   default => 'HMAC-SHA1',
);

=attr signature_key

Where to find the signature key, only used for RSA-SHA1 type signatures.

Expected to be passed a Crypt::OpenSSL::RSA object. Though if passed a 
string, this will be assumped to be a filename and will be passed to 
the new_private_key method of Crypt::OpenSSL::RSA. The object that 
results will be stored.

=method has_signature_key

=method clear_signature_key

=cut

has signature_key => (
   is => 'rw',
   isa => 'SignatureKey',
   coerce => 1,
   predicate => 'has_signature_key',
   clearer => 'clear_signature_key',
);

=method timestamp

Currently just an alias to L<time>, it is used to define the timestamp
of the OAuth request.

=cut

sub timestamp { time };

=method nonce

Define a unique id for every OAuth request, curently this is done by 
taking the md5_hex of two random numbers and the time. 

=cut

sub nonce { md5_hex( join '', rand(2**32), time, rand(2**32) ); };

=attr request_parameters

This is a HashRef of ArrayRefs that is used to define the required
elements of each type of OAuth request. The type (ie request_token)
is the key and all items in the ArrayRef value will be collected 
from $self if not passed at the time that the request is built.

=cut

has request_parameters => (
   is => 'rw',
   isa => 'HashRef[ArrayRef]',
   default => sub{{ request_token => [qw{consumer_key 
                                         consumer_secret 
                                         request_url 
                                         request_method 
                                         signature_key 
                                         signature_method 
                                         protocol_version
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
                                         protocol_version
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
                                         protocol_version
                                         timestamp 
                                         nonce 
                                         token
                                         token_secret
                                        }],
                                         #verifier
   }},
);

=attr exception_handle

Stores a coderef that is called when an exception is hit. Out of 
the box this does not do anything more then die with a message, 
though it can be used to leverage diffrent codepaths at the time
of an exception. 

It is used internaly as such:

  $self->exception_handle->(q{unable to sign request});

Thus if you need to define your own you will have $self and a note
about why it was called. 

I'm not completely happy with this so it could change but this should
get any one needing this the most basic items currently.

=cut

has exception_handle => (
   is => 'rw',
   isa => 'CodeRef',
   default => sub{sub{shift;die @_}},
);

=method build_request

Used to build the Net::OAuth request object based on input and L<gather_request_parts>.

=cut

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

=method gather_request_parts

Uses L<request_parameters> to merge passed items with stored values 
to complete all items required for L<build_request>.

=cut

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

=attr response

Stores the response when any of the get_* methods are called.

=method has_response

=method clear_response

=cut

has response => (
   is => 'rw',
   isa => 'Object', # TODO: this is too vague
   predicate => 'has_response',
   clearer => 'clear_response',
);

=method content

Shortcut to get the content of the response, will return undef if in
the case of no response yet stored.

=cut

sub content {
   my $self = shift;
   ( $self->has_response ) ? $self->response->content : undef;
}

=method success

Shortcut to see if a successful response was collected, returns 0
in the case of no response yet stored.

=cut

sub success {
   my $self = shift;
   return ( $self->has_response ) ? $self->response->is_success : 0;
}

=method failure

Returns the inverse of L<success>.

=cut

sub failure { ! shift->success };

=method error

In the case of a non-successful response, will return a formated 
string that includes the status_line and content to describe the
reason for failure. Will return undef in the case of no response
yet stored.

=cut

sub error{ 
   my $self = shift;
   return ($self->failure) ? join qq{\n}, map{$self->response->$_} qw{status_line content} : undef;
}

=method make_request

Given a Net::OAuth request, convert it to a HTTP::Request such 
that it can be sent via L<ua>. One other thing to note is that
make_request also calls clear_request thus destroying any 
previously stored request.

=cut

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

   my $req = HTTP::Request->new( $request->request_method => ( $request->request_method eq 'GET' && !$self->include_auth_header_for_GET ) 
                                                           ? $request->to_url 
                                                           : $request->request_url
                               );
   $req->content($content) if defined $content;
   return $self->add_auth_headers($req, $request);
}

=attr oauth_header_realm

If defined it is expected to be a string(URL) that will be included
in to the Authorization headers. If not given it will be ignored.

=attr oauth_header_separator

A string that denotes the string that you would like to use to 
seperate the key=value pairs in the Authuntication header.

Defaults to ','.

=cut

has [qw{oauth_header_realm oauth_header_separator}] => (
   is => 'rw',
   isa => 'Maybe[Str]',
);

=method add_auth_headers

Add the Authentication header to the HTTP request based on the OAuth 
request if the request method is POST.

=cut

has include_auth_header_for_GET => (
   is => 'rw',
   isa => 'Bool',
   default => 0,
);

sub build_auth_header {
   my ($self,$oauth_req) = @_;
   $oauth_req->to_authorization_header( 
                                (defined $self->oauth_header_realm) ? $self->oauth_header_realm : undef ,
                                (defined $self->oauth_header_separator) ? $self->oauth_header_separator : undef ,
   );
};


sub add_auth_headers {
   my ($self, $http_req, $oauth_req) = @_;
   $self->exception_handle( 'HTTP::Request expected as first paramater') unless $http_req->isa('HTTP::Request');
   $self->exception_handle( 'Net::OAuth::Message expected as second paramater') unless $oauth_req->isa('Net::OAuth::Message');
   $http_req->authorization( $self->build_auth_header($oauth_req) 
                           ) if $http_req->method eq 'POST' || $self->include_auth_header_for_GET;
   return $http_req;
}

=method send_request

Pass the given HTTP::Request object to L<ua> thus sending out the 
request to the world.

=cut

sub send_request {
   my $self = shift;
   my $req = ( ref($_[0]) && $_[0]->isa('HTTP::Request') ) ? $_[0] : $self->make_request(@_);
   $self->response( $self->ua->request( $req ) );
}

=attr request_token

Stores the request_token when it's collected via L<get_request_token>.

=method has_request_token

=method clear_request_token

=attr request_token_secret

Stores the request_token_secret when it's collected via L<get_request_token>.

=method has_request_token_secret

=method clear_request_token_secret

=attr access_token

Stores the access_token when it's collected via L<get_request_token>.

=method has_access_token

=method clear_access_token

=attr access_token_secret

Stores the access_token_secret when it's collected via L<get_request_token>.

=method has_access_token_secret

=method clear_access_token_secret

=cut

has $_ => (
   is => 'rw',
   isa => 'Str',
   predicate => qq{has_$_},
   clearer => qq{clear_$_},
) for qw{request_token request_token_secret access_token access_token_secret};

=method get_request_token

Builds up an OAuth request to get the request_token pairs.

=cut

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

=method get_authorization_url

Build out the URL that is needed to be called to collect the oauth_verifier.

=cut
   
sub get_authorization_url {
   my $self = shift;
   my %opts = @_;
   $opts{oauth_token} ||= $self->request_token;
   $opts{callback}    ||= $self->callback;
   my $url  = URI->new( $self->authorize_token_url );
   $url->query_form( %opts );
   return $url;
}

=method process_authorization_callback

Unpack the return url from the OAuth provider that includes items
like oauth_verifier. Returns a hash of unparsed items.

=cut

sub process_authorization_callback {
   my $self = shift;
   my $url  = (ref($_[0]) eq '') ? URI->new($_[0]) : $_[0]; # if we are handed a string build a uri object of it
   my %opts = $url->query_form;
   for ( grep{! m/^oauth_/} keys %opts ) {
      delete $opts{$_};
   }
   return %opts;
}

=attr process_access_token_mapping

=cut

has process_access_token_mapping => (
   is => 'rw',
   isa => 'HashRef[ArrayRef]',
   auto_deref => 1,
   default => sub{{ token        => [qw{oauth_token request_token}],
                    token_secret => [qw{request_token_secret}],
                    verifier     => [qw{oauth_verifier}],
                 }},
);

=method process_access_token_input

=cut

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

=method get_access_token

Collect and store the access_tokens.

=cut

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

=method get_protected_resource

=cut

sub get_protected_resource {
   my $self = shift;
   my %opts = (scalar(@_) == 1) ? (request_url => $_[0]) : @_ ; # allow just the requested URL to be pased
   $opts{token} ||= $self->access_token;
   $opts{token_secret} ||= $self->access_token_secret;
   $self->send_request(protected_resource => %opts);
   return $self->success;
}


1;
