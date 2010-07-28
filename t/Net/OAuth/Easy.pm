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
      ok( $oauth->can('build_generic_request'), q{there is a generic request method} );
      ok( my $req = $oauth->build_generic_request('request_token'), q{able to build $req} ); 
      is( ref( $req ), q{Net::OAuth::V1_0A::RequestTokenRequest}, q{$req is the right type});
      ok( $oauth->make_request( $req ) , q{able to make request directly with $req} );
      ok( $oauth->make_request( 'request_token' ), q{able to make request with params} );
      
      ok( $oauth->get_request_token, q{able to collect a request token} );

      ok( $oauth->has_request_token, q{recieved request token} );
      is( $oauth->request_token, 'requestkey', q{recieved correct request token} );
      ok( $oauth->has_request_token_secret, q{recieved request token_secret} );
      is( $oauth->request_token_secret, 'requestsecret', q{recieved correct request token_secret} );


   }
      
}
   

      


1;
