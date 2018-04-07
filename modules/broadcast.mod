#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: broadcast()
#
# Description:
#   Broadcast Module.
#
# Usage:
#   broadcast
#
# Examples:
#   broadcast
#

function broadcast() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="broadcast"
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
  description="Broadcast Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Broadcast Module.

    Commands
    --------

      help                            display module help
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

        printf "_module_variables=(\"%s\")\n" "${_module_variables[@]}" > "$_module_cfg"

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
  "https://nmap.org/nsedoc/scripts/broadcast-avahi-dos.html;\
  ;broadcast-avahi-dos;--script=broadcast-avahi-dos $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-db2-discover.html;\
  ;broadcast-db2-discover;--script db2-discover $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-dhcp-discover.html;\
  ;broadcast-dhcp-discover;--script broadcast-dhcp-discover $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-dhcp6-discover.html;\
  ;broadcast-dhcp6-discover;--script broadcast-dhcp6-discover -6 $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-dns-service-discovery.html;\
  ;broadcast-dns-service-discovery;--script=broadcast-dns-service-discovery $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-dropbox-listener.html;\
  ;broadcast-dropbox-listener;--script=broadcast-dropbox-listener $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-eigrp-discovery.html;\
  ;broadcast-eigrp-discovery;--script=broadcast-eigrp-discovery $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-igmp-discovery.html;\
  ;broadcast-igmp-discovery;--script broadcast-igmp-discovery $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-listener.html;\
  ;broadcast-listener;--script broadcast-listener $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-ms-sql-discover.html;\
  ;broadcast-ms-sql-discover;--script broadcast-ms-sql-discover $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-netbios-master-browser.html;\
  ;broadcast-netbios-master-browser;--script=broadcast-netbios-master-browser $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-novell-locate.html;\
  ;broadcast-novell-locate;--script=broadcast-novell-locate $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-ospf2-discover.html;\
  ;broadcast-ospf2-discover;--script=broadcast-ospf2-discover $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-ping.html;\
  ;broadcast-ping;--script broadcast-ping $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-pppoe-discover.html;\
  ;broadcast-pppoe-discover;--script broadcast-pppoe-discover $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-rip-discover.html;\
  ;broadcast-rip-discover;--script broadcast-rip-discover $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-ripng-discover.html;\
  ;broadcast-ripng-discover;--script broadcast-ripng-discover $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-upnp-info.html;\
  ;broadcast-upnp-info;--script=broadcast-upnp-info $params" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-db2-discover.html;\
  ;broadcast-wake-on-lan;--script broadcast-wake-on-lan $params" \
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
