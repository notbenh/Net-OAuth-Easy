package TEST::Net::OAuth::Easy;
use strict;
use warnings;
use Fennec;

tests load {
   require_ok( 'Net::OAuth::Easy' );
   can_ok( 'Net::OAuth::Easy', qw{
      
      consumer_key 
      consumer_secret 

      request_token_url 
      authorize_token_url
      access_token_url

      request_method 
      signature_method 
      signature_key
      callback 
      protocol

      timestamp 
      nonce 
   });
}

   
describe 'Net::OAuth::Easy' { 

   my $oauth; # will contain a fresh object for each test (build via before_each)

   before_each {
      require_ok( 'Net::OAuth::Easy' );
      $oauth = Net::OAuth::Easy->new;
   }

   it 'will have a method nonce that will generate unique ids' {
      ok( $oauth->can('nonce'), q{we have access to the method} );
      ok( $oauth->nonce ne $oauth->nonce, q{two calls are not identical} );
   }

   it 'will have a single generic request method that all requsets will be run thru' {
      ok( $oauth->can('generic_request'), q{there is a generic request method} );
      #eq_or_diff( $oauth->generic_request( request_token => this => 'that', callback => 'here.com'), {},);

   }
      
}
   

      


1;
