package TEST::Net::OAuth::Easy::Roles::Types;
use strict;
use warnings;
use Fennec;

tests load {
   require_ok( 'Net::OAuth::Easy::Roles::Types' );
}

BEGIN {
   package My::Test;
   use Moose;
   with qw{Net::OAuth::Easy::Roles::Types};
   
   has protocol => (
      is => 'rw',
      isa => 'OAuthProtocol',
   );
   has req_method => (
      is => 'rw',
      isa => 'RequestMethod',
   );
   has sig_method => (
      is => 'rw',
      isa => 'SignatureMethod',
   );
   has sig_key => (
      is => 'rw',
      isa => 'SignatureKey',
   );

   1;
   
};

describe 'Net::OAuth::Easy::Roles::Types' {

   my $t; # place holder for our My::Test object for each test


   before_each {
      $t = My::Test->new;
   };

   it 'is a Moose Role' {
      has_includes( qw{Net::OAuth::Easy::Roles::Types Moose::Role});
   }
   
   it 'will only allow select values to be given for OAuthProtocol' {
      for( qw(1.0 1.0a) ) { 
         ok( $t->protocol($_), sprintf q{able to store %s as protocol}, $_ );
      }
      for( qw(foo bar) ) { 
         dies_ok { $t->protocol($_)} sprintf q{NOT able to store %s as protocol}, $_ ;
      }
   }
      
   it 'will only allow select values to be given for RequestMethod' {
      for( qw(GET POST) ) {
         ok( $t->req_method($_), sprintf q{able to store %s as req_method}, $_ );
      }
      for( qw(foo bar) ) { 
         dies_ok { $t->req_method($_)} sprintf q{NOT able to store %s as req_method}, $_ ;
      }
   }

   it 'will only allow select values to be given for SignatureMethod' {
      for( qw(HMAC-SHA1 RSA-SHA1) ) {
         ok( $t->sig_method($_), sprintf q{able to store %s as sig_method}, $_ );
      }
      for( qw(foo bar) ) { 
         dies_ok { $t->sig_method($_)} sprintf q{NOT able to store %s as sig_method}, $_ ;
      }
   }

   it 'will only allow Crypt::OpenSSL::RSA objects to be stored for sig_key' {
      require_ok( 'Crypt::OpenSSL::RSA' );
      my $rsa = Crypt::OpenSSL::RSA->generate_key(1024);

      ok( $t->sig_key( Crypt::OpenSSL::RSA->new_public_key($rsa->get_public_key_string) ),
          q{able to build sig_key from PKCS1 format}
      );
      ok( $t->sig_key( Crypt::OpenSSL::RSA->new_public_key($rsa->get_public_key_x509_string) ),
          q{able to build sig_key from x509 format}
      );

      use File::Slurp;
   
      if( write_file( 'tmp_key_PKCS1', $rsa->get_public_key_string) ) {
         ok( $t->sig_key('tmp_key_PKCS1'), 
             q{able to take a file name and load that} 
         );
         ok( unlink( 'tmp_key_PKCS1' ), q{clean up our tmp file} );
      }
      else {
         SKIP { ok(1, q{WAS NOT ABLE TO WRITE OUT OUR TEST KEY FOR READING} ); }
      }

      #dies_ok { $t->sig_method($_)} sprintf q{NOT able to store %s as sig_method}, $_ ;
   }

   
}

1;
