package Net::OAuth::Easy::Roles::Types;
use Moose::Role;
use Moose::Util::TypeConstraints;
use File::Slurp;
use Data::Validate::URI qw(is_uri);
require Crypt::OpenSSL::RSA;

enum 'OAuthProtocol' => qw(1.0 1.0a);

enum 'RequestMethod' => qw(GET POST);

enum 'SignatureMethod' => qw(HMAC-SHA1 RSA-SHA1);

subtype SignatureKey => as 'Crypt::OpenSSL::RSA';                                                                                                                                  
coerce  SignatureKey =>
     from Str =>
      via { my $file = $_[0];
            die sprintf q{%s does not exist as a readable file}, $file 
               unless -r $file;
            Crypt::OpenSSL::RSA->new_private_key( join '', read_file($file) );
          };

type ValidURI => as Str => where {is_uri($_)};

1;
