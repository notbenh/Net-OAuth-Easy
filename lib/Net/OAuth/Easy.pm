package Net::OAuth::Easy;
use Moose;

# ABSTRACT: A moose class that abstracts Net::OAuth for you

with qw{
   Net::OAuth::Easy::Roles::Types
};

has protocol => (
   is => 'rw',
   isa => 'OAuthProtocol',
   lazy => 1,
   default => '1.0a',
);

has [qw{ consumer_key consumer_secret }] => (
   is => 'rw',
   isa => 'Str',
);

has [qw{ request_token_url authorize_token_url access_token_url callback }] => (
   is => 'rw',
   isa => 'URI', 
);

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
);



sub timestamp {};
sub nonce {};
     




1;
