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

      request_token 
      request_token_secret 
      access_token 
      access_token_secret

      build_request
      make_request
      send_request

      get_request_token
      get_authorization_url
      get_access_token
   });
}

   
describe 'Net::OAuth::Easy' { 

   my $oauth; # will contain a fresh object for each test (build via before_each)

   before_each {
      require_ok( 'Net::OAuth::Easy' );
      $oauth = Net::OAuth::Easy->new(
         # Thankyou to http://term.ie/oauth/example/ for the sandbox for testing
         consumer_key        => 'key',
         consumer_secret     => 'secret',
         request_token_url   => q{http://term.ie/oauth/example/request_token.php},
         authorize_token_url => q{http://term.ie/oauth/example/access_token.php},
         access_token_url    => q{http://term.ie/oauth/example/echo_api.php},
         callback            => q{http://here.com},
      );
   }

   it 'will have a method nonce that will generate unique ids' {
      ok( $oauth->can('nonce'), q{we have access to the method} );
      ok( $oauth->nonce ne $oauth->nonce, q{two calls are not identical} );
   }

   it 'will have a single generic request method that all requsets will be run thru' {
      ok( $oauth->can('build_request'), q{there is a generic request method} );
      ok( my $req = $oauth->build_request('request_token'), q{able to build $req} ); 
      is( ref( $req ), q{Net::OAuth::V1_0A::RequestTokenRequest}, q{$req is the right type});
      ok( $oauth->make_request( $req ) , q{able to make request directly with $req} );
      ok( $oauth->make_request( 'request_token' ), q{able to make request with params} );
   }

   it 'will be able to collect tokens and store them with in the object' {
      
      ok( $oauth->get_request_token, q{able to collect a pair of request token} );

      ok( $oauth->has_request_token, q{recieved request token} );
      is( $oauth->request_token, 'requestkey', q{recieved correct request token} );
      ok( $oauth->has_request_token_secret, q{recieved request token_secret} );
      is( $oauth->request_token_secret, 'requestsecret', q{recieved correct request token_secret} );

      ok( $oauth->get_access_token(verifier => 'kitten'), 
          q{able to collect a pair of access tokens} 
      );
      
      ok( $oauth->has_access_token, q{recieved access token} );
      is( $oauth->access_token, 'accesskey', q{recieved correct access token} );
      ok( $oauth->has_access_token_secret, q{recieved access token_secret} );
      is( $oauth->access_token_secret, 'accesssecret', q{recieved correct access token_secret} );


   }
      
}
   

      


1;
