## OpenCA::RBAC
##
## Copyright (C) 2000-2001 Michael Bell (michael.bell@web.de)
##

use strict;

package OpenCA::RBAC;

use OpenCA::DBI;
use OpenCA::DBIS;
use OpenCA::X509;
use OpenCA::OpenSSL;
use OpenCA::Tools;

## the other use directions depends from the used databases
## $Revision: 1.7 $

$OpenCA::RBAC::VERSION = '0.2.0';

$OpenCA::RBAC::ERROR = {
  FORBIDDEN            => -1,
  DN_NOT_EXIST         => -101,
  DN_NOT_DISTINGUISHED => -102,
  SEARCHITEM_FAILED    => -103,
  GETITEM_FAILED       => -104
                      };

## format is status, operation
$OpenCA::RBAC::OBJECT = {
  REQUEST => 
    [
     "NONEXISTENT",
     "PENDING"    ,
     "APPROVED"   ,
     "ARCHIVIED"  ,
     "DELETED"    ,
     "ANY"
    ],
  CA_CERTIFICATE =>
    [
     "NONEXISTENT",
     "VALID"      ,
     "EXPIRED"    ,
     "REVOKED"    ,
     "SUSPENDED"  ,
     "ANY"
    ],
  CERTIFICATE =>
    [
     "NONEXISTENT",
     "VALID"      ,
     "EXPIRED"    ,
     "REVOKED"    ,
     "SUSPENDED"  ,
     "ANY"
    ],
  CRR =>
    [
     "NONEXISTENT",
     "PENDING"    ,
     "APPROVED"   ,
     "ARCHIVIED"  ,
     "DELETED"    ,
     "ANY"
    ],
  CRL =>
    [
     "NONEXISTENT",
     "VALID"      ,
     "EXPIRED"    ,
     "ANY"
    ],
  RBAC =>
   [
     "IMPORT",
     "ANY"
   ],
  LDAP =>
   [
     "ANY"
   ],
  DATABASE =>
   [
     "ANY"
   ]
};

@OpenCA::RBAC::VARIABLE = (
                           "SERIAL",
                           "ROLE",
                           "OBJECT",
                           "STATUS",
                           "OWNER",
                           "OPERATION"
                          );

my $params = {
	      SHELL         => undef,
	      DB            => undef,

              CERT_FILE     => undef,
              KEY_FILE      => undef,
              PASSWD        => undef,
              MESSAGEKEY    => undef,
              MESSAGELENGTH => undef,
              DAEMON        => undef,

              RBAC_SERIAL => undef,
              ROLE        => undef,
              RIGHT       => undef,
              OBJECT      => undef,
              STATUS      => undef,
              OWNER       => undef,
              OPERATION   => undef,
              FORMAT      => undef,
              DATA        => undef,
              INFO        => undef,
 
              TOOLS         => undef,
              ITEM          => undef,
              DEBUG         => 0
	     };

sub new { 
  
  # no idea what this should do
  
  my $that  = shift;
  my $class = ref($that) || $that;
  
  ## my $self  = $params;
  my $self;
  my $help;
  ## deep copy
  foreach $help (keys %{$params}) {
    $self->{$help} = $params->{$help};
  }
   
  bless $self, $class;

  # ok here I start ;-)

  $self->init (@_);

  return $self;
}

sub sign {

  my $self = shift;
  my $keys = { @_ };
 
  $self->init (@_);

  my $i = $self->getParsed ();
  delete $i->{ITEM};
  delete $i->{DATA};
  delete $i->{TYPE};
  delete $i->{FORMAT};

  my $data = OpenCA::DBIS->getMergedData ($i);

  $self->{SIGNATURE} = OpenCA::DBIS->getSignature (
                    CERT_FILE     => $self->{CERT_FILE},
                    KEY_FILE      => $self->{KEY_FILE},
                    PASSWD        => $self->{PASSWD},
                    MESSAGEKEY    => $self->{MESSAGEKEY},
                    MESSAGELENGTH => $self->{MESSAGELENGTH},
                    DATA          => $data
                   );
}

sub getParsed {

  my $self = shift;
 
  my $help;

  ## scan all lines until not a regular variable
  my $data = $self->{DATA};
  my $signature = 0;

  my @lines = split ( /\n/, $data );

  my $i;
  my ($key, $val);
  for ($i=0; $i< scalar (@lines); $i++) {
    if ( $lines [$i] =~ /.*=.*/ ) {
      $lines [$i] =~ s/\s*=\s*/=/g;
      ( $key, $val ) = ( $lines [$i] =~ /(.*)\s*=\s*(.*)\s*/ );
      $self->{$key} = $val;
    } else {
      $self->{SIGNATURE} .= $lines [$i];
    }
  }                 

  ## setup hash;
  my $result;
  my $var;
  foreach $var (@OpenCA::RBAC::VARIABLE) {
    $result->{$var} = $self->{$var};
  }
  $result->{FORMAT} = "TXT";
  $result->{TYPE}   = "TXT";
  # $self->{TYPE}   = "TXT";

  $result->{ITEM}   = $self->{DATA};

  ## print $result->{ITEM}."###".$self->{DATA}."<br>\n";

  return $result;
 
}

sub verify {

  my $self = shift;
  my $keys = { @_ };
 
  $self->init (@_);

  ## if this is a final version then it is a bug

  return 1;
}

sub getMenu {

  my $self = shift;
  my $keys = { @_ };

  my $help;
  my $h_help;
  my @result;

  ## show the objecttypes
  if ( not $keys->{OBJECT} ) {
    foreach $help (keys %{$OpenCA::RBAC::OBJECT}) {
      ## print $help."\n";
      push (@result, $help);
    }
    return @result;
  }

  return @{$OpenCA::RBAC::OBJECT->{$keys->{OBJECT}}};

}

#######################
## private functions ##
#######################

sub init {
  my $self = shift;
  my $keys = { @_ };
 
  $self->{DEBUG} = $keys->{DEBUG} if ($keys->{DEBUG});
 
  print "  sub init of OpenCA::RBAC\n" if ($self->{DEBUG});

  print "   load cryptoconfig\n" if ($self->{DEBUG});

  ## signing will be configured
  $self->{CERT_FILE} = $keys->{CERT_FILE} if ($keys->{CERT_FILE});
  $self->{KEY_FILE}  = $keys->{KEY_FILE}  if ($keys->{KEY_FILE});
  $self->{PASSWD}    = $keys->{PASSWD}    if ($keys->{PWD});

  ## checking for given messagequeue
  $self->{MESSAGEKEY}    = $keys->{MESSAGEKEY}    if ($keys->{MESSAGEKEY});
  $self->{MESSAGELENGTH} = $keys->{MESSAGELENGTH} if ($keys->{MESSAGELENGTH});
  $self->{DAEMON}        = $keys->{DAEMON}        if ($keys->{DAEMON});

  ## if new called from getItem
  ##  => SHELL, FORMAT, DATA

  $self->{SHELL}  = $keys->{SHELL}  if ($keys->{SHELL});
  $self->{FORMAT} = $keys->{FORMAT} if ($keys->{FORMAT});
  $self->{FORMAT} = $keys->{INFORM} if ($keys->{INFORM});
  $self->{DATA}   = $keys->{DATA}   if ($keys->{DATA});

  ## if DATA => getItem or import
  if ($self->{DATA}) {
    print "  called from getItem or import\n" if ($self->{DEBUG});
    if ( $self->getParsed () ) {
      return 1;
    } else {
      return 0;
    }
  }

  $self->{SERIAL}      = $keys->{SERIAL}      if ($keys->{SERIAL});
  $self->{ROLE}        = $keys->{ROLE}        if ($keys->{ROLE});
  $self->{OBJECT}      = $keys->{OBJECT}      if ($keys->{OBJECT});
  $self->{STATUS}      = $keys->{STATUS}      if ($keys->{STATUS});
  $self->{OWNER}       = $keys->{OWNER}       if ($keys->{OWNER});
  $self->{OPERATION}   = $keys->{OPERATION}   if ($keys->{OPERATION});

  ## made rbac storeable
  my $var;
  ## print "used <br>\n";
  if ( not $self->{DATA} ) {
    foreach $var (@OpenCA::RBAC::VARIABLE) {
      ## print "var_data: ".$var."<br>\n";
      $self->{DATA} .= $var."=".$self->{$var}."\n";
    }
    if ( not $self->{SIGNATURE} ) {
      $self->sign;
    }
    $self->{DATA} .= $self->{SIGNATURE};
  }

  ## if only ROLE  => new role
  if ( $self->{ROLE} and not
       (
        $self->{SERIAL} or
        $self->{OBJECT} or
        $self->{STATUS} or
        $self->{OWNER} or
        $self->{OPERATION}
       )
     ) {
    print "  new role ...\n" if ($self->{DEBUG});
    return 1;
  }

  print "  normal role ...\n" if ($self->{DEBUG});


  return 1;
}

sub debug {
  my $self = shift;

  if ($self->{DEBUG}) {

    print "    BACKEND       true\n" if ($self->{SHELL});
    print "    BACKEND       false\n" if (not $self->{SHELL});
    print "    DB            true\n" if ($self->{DB});
    print "    DB            false\n" if (not $self->{DB});
    print "    ITEM          ".$self->{ITEM}."\n";

    print "    CERT_FILE     ".$self->{CERT_FILE}."\n";
    print "    KEY_FILE      ".$self->{KEY_FILE}."\n";
    print "    PWD           ".$self->{PWD}."\n";

    print "    MESSAGEKEY    ".$self->{MESSAGEKEY}."\n";
    print "    MESSAGELENGTH ".$self->{MESSAGELENGTH}."\n";
    print "    DAEMON        ".$self->{DAEMON}."\n";

    print "    RBAC_SERIAL ".$self->{RBAC_SERIAL}."\n";
    print "    ROLE        ".$self->{ROLE}."\n";
    print "    RIGHT       ".$self->{RIGHT}."\n";
    print "    OBJECT      ".$self->{OBJECT}."\n";
    print "    STATUS      ".$self->{STATUS}."\n";
    print "    OWNER       ".$self->{OWNER}."\n";
    print "    OPERATION   ".$self->{OPERATION}."\n";
    print "    FORMAT      ".$self->{FORMAT}."\n";
    print "    DATA        ".$self->{DATA}."\n";
    print "    INFO        ".$self->{INFO}."\n";

  }
  return;
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!
  
=head1 NAME
  
OpenCA::RBAC - Perl Certificates RBAC Extention.
 
=head1 SYNOPSIS
  
use OpenCA::RBAC;
 
=head1 DESCRIPTION

Attention this is not a documentation. Only dummy from OpenCA::RBAC alpha!!!
  
=head1 AUTHOR
 
Michael Bell <loon@openca.org>
 
=head1 SEE ALSO
 
OpenCA::OpenSSL, OpenCA::X509, OpenCA::CRL, OpenCA::REQ,
OpenCA::TRIStateCGI, OpenCA::Configuration, OpenCA::Tools
 
=cut                                                                                         
