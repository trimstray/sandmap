#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_other-services()
#
# Description:
#   NSE Other Services Module.
#
# Usage:
#   nse_other-services
#
# Examples:
#   nse_other-services
#

function nse_other-services() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_other-services"
  local _STATE=0

  # User variables:
  # - module_name: store module name
  # - module_args: store module arguments

  export _module_show=
  export _module_help=
  export _module_opts=
  export _module_commands=

  # shellcheck disable=SC2034
  _module_variables=()

  # shellcheck disable=SC2034
  author="trimstray"
  contact="trimstray@gmail.com"
  version="1.0"
  description="NSE Other Services Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE Other Services Module.

    Commands
    --------

      help    <module>                display module or NSE help
      show    <key>                   display module or profile info
      config  <key>                   show module configuration
      set     <key>                   set module variable value
      use     <module>                reuse module (changed env)
      pushd   <key>|init|show|flush   command line commands stack
      search  <key>                   search key in all commands
      init    <alias|id>              run profile

      Options:

        <key>                         key value
        <value>                       profile alias or id

")

  # shellcheck disable=SC2154
  if [[ "$_mstate" -eq 0 ]] ; then

    if [[ -e "$_module_cfg" ]] && [[ -s "$_module_cfg" ]] ; then

      # shellcheck disable=SC1090
      source "$_module_cfg"

    else

      # shellcheck disable=SC2034
      _module_variables=()

      if [[ "${#_module_variables[@]}" -ne 0 ]] ; then

        printf "_module_variables=(\"%s\")\\n" "${_module_variables[@]}" > "$_module_cfg"

      fi

      _mstate=1

    fi

  else

    # shellcheck disable=SC1090
    source "$_module_cfg"

  fi

  # In the given commands you can use variables from the CLI config
  # command or the etc/main.cfg file.

  # shellcheck disable=SC2034
  _module_commands=(\
  #
  "https://nmap.org/nsedoc/scripts/amqp-info.html;\
  ;amqp-info;--script=amqp-info" \
  #
  "https://nmap.org/nsedoc/scripts/auth-owners.html;\
  ;auth-owners;--script=auth-owners" \
  #
  "https://nmap.org/nsedoc/scripts/auth-spoof.html;\
  ;auth-spoof;--script=auth-spoof" \
  #
  "https://nmap.org/nsedoc/scripts/bittorrent-discovery.html;\
  ;bittorrent-discovery;--script=bittorrent-discovery" \
  #
  "https://nmap.org/nsedoc/scripts/cassandra-brute.html;\
  ;cassandra-brute;--script=cassandra-brute" \
  #
  "https://nmap.org/nsedoc/scripts/cassandra-info.html;\
  ;cassandra-info;--script=cassandra-info" \
  #
  "https://nmap.org/nsedoc/scripts/clamav-exec.html;\
  ;clamav-exec;--script=clamav-exec" \
  #
  "https://nmap.org/nsedoc/scripts/cups-info.html;\
  ;cups-info;--script=cups-info" \
  #
  "https://nmap.org/nsedoc/scripts/cups-queue-info.html;\
  ;cups-queue-info;--script=cups-queue-info" \
  #
  "https://nmap.org/nsedoc/scripts/cvs-brute-repository.html;\
  ;cvs-brute-repository;--script=cvs-brute-repository" \
  #
  "https://nmap.org/nsedoc/scripts/cvs-brute.html;\
  ;cvs-brute;--script=cvs-brute" \
  #
  "https://nmap.org/nsedoc/scripts/daytime.html;\
  ;daytime;--script=daytime" \
  #
  "https://nmap.org/nsedoc/scripts/docker-version.html;\
  ;docker-version;--script=docker-version" \
  #
  "https://nmap.org/nsedoc/scripts/hddtemp-info.html;\
  ;hddtemp-info;--script=hddtemp-info" \
  #
  "https://nmap.org/nsedoc/scripts/ike-version.html;\
  ;ike-version;--script=ike-version" \
  #
  "https://nmap.org/nsedoc/scripts/ipmi-brute.html;\
  ;ipmi-brute;--script=ipmi-brute" \
  #
  "https://nmap.org/nsedoc/scripts/ipmi-cipher-zero.html;\
  ;ipmi-cipher-zero;--script=ipmi-cipher-zero" \
  #
  "https://nmap.org/nsedoc/scripts/ipmi-version.html;\
  ;ipmi-version;--script=ipmi-version" \
  #
  "https://nmap.org/nsedoc/scripts/iscsi-brute.html;\
  ;iscsi-brute;--script=iscsi-brute" \
  #
  "https://nmap.org/nsedoc/scripts/iscsi-info.html;\
  ;iscsi-info;--script=iscsi-info" \
  #
  "https://nmap.org/nsedoc/scripts/ldap-brute.html;\
  ;ldap-brute;--script=ldap-brute" \
  #
  "https://nmap.org/nsedoc/scripts/ldap-novell-getpass.html;\
  ;ldap-novell-getpass;--script=ldap-novell-getpass" \
  #
  "https://nmap.org/nsedoc/scripts/ldap-rootdse.html;\
  ;ldap-rootdse;--script=ldap-rootdse" \
  #
  "https://nmap.org/nsedoc/scripts/ldap-search.html;\
  ;ldap-search;--script=ldap-search" \
  #
  "https://nmap.org/nsedoc/scripts/memcached-info.html;\
  ;memcached-info;--script=memcached-info" \
  #
  "https://nmap.org/nsedoc/scripts/nfs-ls.html;\
  ;nfs-ls;--script=nfs-ls" \
  #
  "https://nmap.org/nsedoc/scripts/nfs-showmount.html;\
  ;nfs-showmount;--script=nfs-showmount" \
  #
  "https://nmap.org/nsedoc/scripts/nfs-statfs.html;\
  ;nfs-statfs;--script=nfs-statfs" \
  #
  "https://nmap.org/nsedoc/scripts/nntp-ntlm-info.html;\
  ;nntp-ntlm-info;--script=nntp-ntlm-info" \
  #
  "https://nmap.org/nsedoc/scripts/nrpe-enum.html;\
  ;nrpe-enum;--script=nrpe-enum" \
  #
  "https://nmap.org/nsedoc/scripts/ntp-info.html;\
  ;ntp-info;--script=ntp-info" \
  #
  "https://nmap.org/nsedoc/scripts/ntp-monlist.html;\
  ;ntp-monlist;--script=ntp-monlist" \
  #
  "https://nmap.org/nsedoc/scripts/puppet-naivesigning.html;\
  ;puppet-naivesigning;--script=puppet-naivesigning" \
  #
  "https://nmap.org/nsedoc/scripts/redis-brute.html;\
  ;redis-brute;--script=redis-brute" \
  #
  "https://nmap.org/nsedoc/scripts/redis-info.html;\
  ;redis-info;--script=redis-info" \
  #
  "https://nmap.org/nsedoc/scripts/rexec-brute.html;\
  ;rexec-brute;--script=rexec-brute" \
  #
  "https://nmap.org/nsedoc/scripts/riak-http-info.html;\
  ;riak-http-info;--script=riak-http-info" \
  #
  "https://nmap.org/nsedoc/scripts/rpc-grind.html;\
  ;rpc-grind;--script=rpc-grind" \
  #
  "https://nmap.org/nsedoc/scripts/rpcinfo.html;\
  ;rpcinfo;--script=rpcinfo" \
  #
  "https://nmap.org/nsedoc/scripts/rsync-brute.html;\
  ;rsync-brute;--script=rsync-brute" \
  #
  "https://nmap.org/nsedoc/scripts/rsync-list-modules.html;\
  ;rsync-list-modules;--script=rsync-list-modules" \
  #
  "https://nmap.org/nsedoc/scripts/rtsp-methods.html;\
  ;rtsp-methods;--script=rtsp-methods" \
  #
  "https://nmap.org/nsedoc/scripts/rtsp-url-brute.html;\
  ;rtsp-url-brute;--script=rtsp-url-brute" \
  #
  "https://nmap.org/nsedoc/scripts/rusers.html;\
  ;rusers;--script=rusers" \
  #
  "https://nmap.org/nsedoc/scripts/sip-brute.html;\
  ;sip-brute;--script=sip-brute" \
  #
  "https://nmap.org/nsedoc/scripts/sip-call-spoof.html;\
  ;sip-call-spoof;--script=sip-call-spoof" \
  #
  "https://nmap.org/nsedoc/scripts/sip-enum-users.html;\
  ;sip-enum-users;--script=sip-enum-users" \
  #
  "https://nmap.org/nsedoc/scripts/sip-methods.html;\
  ;sip-methods;--script=sip-methods" \
  #
  "https://nmap.org/nsedoc/scripts/skypev2-version.html;\
  ;skypev2-version;--script=skypev2-version" \
  #
  "https://nmap.org/nsedoc/scripts/supermicro-ipmi-conf.html;\
  ;supermicro-ipmi-conf;--script=supermicro-ipmi-conf" \
  #
  "https://nmap.org/nsedoc/scripts/svn-brute.html;\
  ;svn-brute;--script=svn-brute" \
  #
  "https://nmap.org/nsedoc/scripts/upnp-info.html;\
  ;upnp-info;--script=upnp-info" \
  #
  "https://nmap.org/nsedoc/scripts/vmauthd-brute.html;\
  ;vmauthd-brute;--script=vmauthd-brute" \
  #
  "https://nmap.org/nsedoc/scripts/vmware-version.html;\
  ;vmware-version;--script=vmware-version" \
  )

  # shellcheck disable=SC2034,SC2154
  _module_show=(\
      "${module_name}" \
      "${version}" \
      "${#_module_commands[@]}" \
      "${author}" \
      "${contact}" \
      "${description}" \
      )

  # shellcheck disable=SC2034
  export _module_opts=(\
  "$_module_help")

  return $_STATE

}
