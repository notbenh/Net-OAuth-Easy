package Net::OAuth::Easy;
use Moose;
use Moose::Util::TypeConstraints;
use File::Slurp;

# ABSTRACT: A moose class that abstracts Net::OAuth for you

enum 'OAuthProtocol' => qw(1.0 1.0a);
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



=pod
  subtype 'Natural'
      => as 'Int'
      => where { $_ > 0 };

  subtype 'NaturalLessThanTen'
      => as 'Natural'
      => where { $_ < 10 }
      => message { "This number ($_) is not less than ten!" };

  coerce 'Num'
      => from 'Str'
        => via { 0+$_ };

=cut


enum 'RequestMethod' => qw(GET POST);
has request_method => (
   is => 'rw',
   isa => 'RequestMethod',
   default => 'GET',
);

enum 'SignatureMethod' => qw(HMAC-SHA1 RSA-SHA1);
has signature_method => (
   is => 'rw',
   isa => 'RequestMethod',
   default => 'GET',
);

type SignatureKey => as 'Crypt::OpenSSL::RSA';
coerce SignatureKey => 
     from Str => 
      via { die sprintf q{%s does not exist as a readable file} unless -r $_;
            Crypt::OpenSSL::RSA->new_private_key( join '', read_file($_) );
          };
has signature_key => (
   is => 'rw',
   isa => 'SignatureKey',
);



sub timestamp {};
sub nonce {};
     




1;
