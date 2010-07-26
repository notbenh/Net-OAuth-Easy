package Net::OAuth::Easy;
use Moose;

# ABSTRACT: A moose class that abstracts Net::OAuth for you

has oauth => (
   is => 'rw',
   isa => 'Net::OAuth',
   lazy => 1,
   default => sub{
      require Net::OAuth;
      Net::OAuth->new;
   },
);


1;
