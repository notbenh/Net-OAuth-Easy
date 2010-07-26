package TEST::Net::OAuth::Easy;
use strict;
use warnings;
use Fennec;

tests load {
   require_ok( 'Net::OAuth::Easy' );
   can_ok( 'Net::OAuth::Easy', qw{
      oauth
   });
}

1;
