package Net::OAuth::Easy::Roles::Types;
use Moose::Role;
use Moose::Util::TypeConstraints;
use File::Slurp;

enum 'OAuthProtocol' => qw(1.0 1.0a);

enum 'RequestMethod' => qw(GET POST);

enum 'SignatureMethod' => qw(HMAC-SHA1 RSA-SHA1);

type SignatureKey => as 'Crypt::OpenSSL::RSA';
coerce SignatureKey => 
     from Str => 
      via { die sprintf q{%s does not exist as a readable file} unless -r $_;
            Crypt::OpenSSL::RSA->new_private_key( join '', read_file($_) );
          };



