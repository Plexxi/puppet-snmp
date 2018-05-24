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
  Enum['present', 'absent'] $ensure,
  String[8] $authpass,
  Enum['SHA', 'MD5'] $authtype          = 'SHA',
  Optional[String[8]] $privpass            = undef,
  Enum['AES', 'DES'] $privtype          = 'AES',
  Enum['snmpd', 'snmptrapd'] $daemon    = 'snmpd',
) {

  include ::snmp

  if ($daemon == 'snmptrapd') and ($::osfamily != 'Debian') {
    $service_name   = 'snmptrapd'
    $service_before = Service['snmptrapd']
  } else {
    $service_name   = 'snmpd'
    $service_before = Service['snmpd']
  }

  if $ensure == 'present' {
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
      umask   => '0077',
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
