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
      $oauth = Net::OAuth::Easy->new(
         consumer_key        => 'googlecodesamples.com',
         consumer_secret     => 'turkey',
         request_token_url   => q{https://www.google.com/accounts/OAuthGetRequestToken},
         authorize_token_url => q{https://www.google.com/accounts/OAuthAuthorizeToken},
         access_token_url    => q{https://www.google.com/accounts/OAuthGetAccessToken},
      );
   }

   it 'will have a method nonce that will generate unique ids' {
      ok( $oauth->can('nonce'), q{we have access to the method} );
      ok( $oauth->nonce ne $oauth->nonce, q{two calls are not identical} );
   }

   it 'will have a single generic request method that all requsets will be run thru' {
      ok( $oauth->can('build_generic_request'), q{there is a generic request method} );
      ok( my $req = $oauth->build_generic_request( request_token => callback => 'here.com') ); 
      is( ref( $req ), q{Net::OAuth::V1_0A::RequestTokenRequest});
      ok( $oauth->make_request( $req ) );
      ok( $oauth->make_request( request_token => callback => 'here.com' ) );

      #eq_or_diff( $oauth->response, {} );

   }
      
}
   

      


1;
