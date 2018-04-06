# == Definition: snmp::snmpv3_user
#
# This definition creates a SNMPv3 user.
#
# === Parameters:
#
# [*title*]
#   Name of the user.
#   Required
#
# [*ensure*]
#   Indicate if user should be present or absent.
#   Required
#
# [*authpass*]
#   Authentication password for the user.
#   Required (even if 'ensure' is absent)
#
# [*authtype*]
#   Authentication type for the user.  SHA or MD5
#   Default: SHA
#
# [*privpass*]
#   Encryption password for the user.
#   Default: no encryption password
#
# [*privtype*]
#   Encryption type for the user.  AES or DES
#   Default: AES
#
# [*daemon*]
#   Which daemon file in which to write the user.  snmpd or snmptrapd
#   Default: snmpd
#
# === Actions:
#
# Creates a SNMPv3 user with authentication and encryption paswords.
#
# === Requires:
#
# Class['snmp']
#
# === Sample Usage:
#
#   snmp::snmpv3_user { 'myuser':
#     authtype => 'MD5',
#     authpass => '1234auth',
#     privpass => '5678priv',
#   }
#
# === Authors:
#
# Mike Arnold <mike@razorsedge.org>
#
# === Copyright:
#
# Copyright (C) 2012 Mike Arnold, unless otherwise noted.
#
define snmp::snmpv3_user (
  $ensure,
  $authpass,
  $authtype = 'SHA',
  $privpass = undef,
  $privtype = 'AES',
  $daemon   = 'snmpd',
) {

  include ::snmp

  $ensure_options = [ '^present$', '^absent$', ]
  validate_re($ensure, $ensure_options, "ensure must be either 'present' or 'absent'")

  if ($daemon == 'snmptrapd') and ($::osfamily != 'Debian') {
    $service_name   = 'snmptrapd'
    $service_before = Service['snmptrapd']
  } else {
    $service_name   = 'snmpd'
    $service_before = Service['snmpd']
  }

  if $ensure == 'present' {
    # Validate our regular expressions
    $hash_options = [ '^SHA$', '^MD5$' ]
    validate_re($authtype, $hash_options, '$authtype must be either SHA or MD5.')
    $enc_options = [ '^AES$', '^DES$' ]
    validate_re($privtype, $enc_options, '$privtype must be either AES or DES.')
    $daemon_options = [ '^snmpd$', '^snmptrapd$' ]
    validate_re($daemon, $daemon_options, '$daemon must be either snmpd or snmptrapd.')
    validate_re($authpass, '^.{8,}$', 'authpass must be minimum 8 characters long.')
    if $privpass {
      validate_re($privpass, '^.{8,}$', 'privpass must be minimum 8 characters long.')
    }

    $tmpfile = "/tmp/.${title}-${daemon}"
    if $privpass {
      $createcmd = "echo \"${authpass}${authtype}${privpass}${privtype}\" | sha1sum > ${tmpfile}"
      $engagecmd = "createUser ${title} ${authtype} \\\"${authpass}\\\" ${privtype} \\\"${privpass}\\\""
    } else {
      $createcmd = "echo \"${authpass}${authtype}${privtype}\" | sha1sum > ${tmpfile}"
      $engagecmd = "createUser ${title} ${authtype} \\\"${authpass}\\\""
    }

    exec { "create-snmpv3-user-${title}":
      path    => '/bin:/sbin:/usr/bin:/usr/sbin',
      command => $createcmd,
      user    => 'root',
      umask   => 0077,
    } -> exec { "engage-snmpv3-user-${title}":
      path    => '/bin:/sbin:/usr/bin:/usr/sbin',
      command => "systemctl stop ${service_name} ; sleep 2 ; echo \"${engagecmd}\" >>${snmp::params::var_net_snmp}/${daemon}.conf && mv ${tmpfile} ${snmp::params::var_net_snmp}/${title}-${daemon} ; systemctl start ${service_name}",
      unless => "cmp -s ${tmpfile} ${snmp::params::var_net_snmp}/${title}-${daemon}",
      user    => 'root',
      require => [ Package['snmpd'], File['var-net-snmp'], ],
      before  => $service_before,
    }

  } else {
    exec { "remove-snmpv3-user-${title}":
      path    => '/bin:/sbin:/usr/bin:/usr/sbin',
      command => "systemctl stop ${service_name} ; sleep 2 ; sed -i 's/^.*\"${title}\" \"${title}\".*$//' ${snmp::params::var_net_snmp}/${daemon}.conf ; rm -f ${snmp::params::var_net_snmp}/${title}-${daemon} ; systemctl start ${service_name}",
      onlyif  => "test -f ${snmp::params::var_net_snmp}/${title}-${daemon}",
      user    => 'root',
      require => [ Package['snmpd'], File['var-net-snmp'], ],
      before  => $service_before,
    } 
  }
}
