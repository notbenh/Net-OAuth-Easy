package TEST::Net::OAuth::Easy;
use strict;
use warnings;
use Fennec;
use Test::WWW::Mechanize;

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


# !!!! CASE FOR BOTH RSA AND HMAC

   
describe 'Net::OAuth::Easy' { 

   my $oauth; # will contain a fresh object for each test (build via before_each)

   before_each {
      require_ok( 'Net::OAuth::Easy' );
      $oauth = Net::OAuth::Easy->new(
         # Thank you to http://oauth-sandbox.sevengoslings.net/ for providing a sandbox
         consumer_key        => '99b23d82e268e527',
         consumer_secret     => '08dfedff683f96b9a87401cf5d41',
         request_token_url   => q{http://oauth-sandbox.sevengoslings.net/request_token},
         authorize_token_url => q{http://oauth-sandbox.sevengoslings.net/authorize},
         access_token_url    => q{http://oauth-sandbox.sevengoslings.net/access_token},
         callback            => q{http://search.cpan.org/search?query=notbenh&mode=all},
      );
   }

   it 'will have a method nonce that will generate unique ids' {
      ok( $oauth->can('nonce'), q{we have access to the method} );
      ok( $oauth->nonce ne $oauth->nonce, q{no two nonce calls are identical} );
   }

   it 'will have a single generic request method that all requsets will be run thru' {
      ok( $oauth->can('build_request'), q{there is a generic request method} );
      ok( my $req = $oauth->build_request('request_token'), q{able to build $req} ); 
      is( ref( $req ), q{Net::OAuth::V1_0A::RequestTokenRequest}, q{$req is the right type});
      ok( $oauth->make_request( $req ) , q{able to make request directly with $req} );
      ok( $oauth->make_request( 'request_token' ), q{able to make request with params} );
   }

   it 'will complete a simple workflow of getting OAuth tokens' {
      
      ok( $oauth->get_request_token, q{able to collect a pair of request token} );

      ok( $oauth->has_request_token, q{recieved request token} );
      ok( $oauth->has_request_token_secret, q{recieved request token_secret} );

      ok( my $auth_url = $oauth->get_authorization_url, q{able to generate an auth url} );
      like( $auth_url, qr{http://oauth-sandbox.sevengoslings.net/authorize}, q{auth url has the right base});
      like( $auth_url, qr{oauth_token}, q{auth url includes token} );
      like( $auth_url, qr{callback},    q{auth url includes callback} );

      ok( my $mech = Test::WWW::Mechanize->new, q{built up a mech object for the web part of the tests});
      $mech->get_ok( $auth_url );
      $mech->content_contains( '<button id="need_login">Login</button>', q{need to log in} );

      $mech->submit_form_ok( {form_name   => 'teh_form',
                              with_fields => { username => 'notbenh',
                                               kitten   => 'fox',
                                             },
                             }
      );

      $mech->content_contains( '<input type="submit" name="allow" value="Allow Access" />',
                               q{need to accept connection}
                             );
      $mech->click_ok('allow');

      ok( $oauth->get_access_token( $mech->uri ),
          q{able to collect a pair of access tokens} 
      );
      
      ok( $oauth->has_access_token, q{recieved access token} );
      ok( $oauth->has_access_token_secret, q{recieved access token_secret} );


      ok( $oauth->get_protected_resource('http://oauth-sandbox.sevengoslings.net/three_legged'),
          q{able to make a request for a procted resource},
      );
      ok( $oauth->success, q{call was made successfuly} );
      like( $oauth->content, qr/SUCCESS!/, q{content validates} );

   }


   after_all {
      my $mech = Test::WWW::Mechanize->new;
      $mech->get(q{http://oauth-sandbox.sevengoslings.net});
      $mech->submit_form_ok( {form_name   => 'teh_form',
                              with_fields => { username => 'notbenh',
                                               kitten   => 'fox',
                                             },
                             }
      );

      while ( grep{defined $_->text && $_->text eq 'Revoke Access' } $mech->links ) {
         $mech->follow_link( text => 'Revoke Access');
      };
   }
      
}
   

      


1;
