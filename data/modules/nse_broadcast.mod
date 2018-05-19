#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_broadcast()
#
# Description:
#   NSE Broadcast Module.
#
# Usage:
#   nse_broadcast
#
# Examples:
#   nse_broadcast
#

function nse_broadcast() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_broadcast"
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
  description="NSE Broadcast Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s: \\e[1;32m%s\\e[m" "
  Module" "${module_name}")

  _module_help+=$(printf "\\n%s" "
    Description
    -----------

      NSE Broadcast Module.

    Commands
    --------

      help    <module>                display module or NSE help
      show    <key>                   display module or profile info
      config  <key>                   show module configuration
      set     <key>                   set module variable value
      use     <module>                reuse module (changed env)
      pushd   <key>|init|show|flush   command line commands stack
      search  <key>                   search key in all commands
      init    <alias|id> [--args]     run profile

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
  "https://nmap.org/nsedoc/scripts/broadcast-avahi-dos.html;\
  ;broadcast-avahi-dos;--script=broadcast-avahi-dos;\
  \"broadcast-avahi-dos.wait=20\"" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-db2-discover.html;\
  ;broadcast-db2-discover;--script=db2-discover" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-dhcp-discover.html;\
  ;broadcast-dhcp-discover;--script=broadcast-dhcp-discover;\
  \"broadcast-dhcp-discover.timeout=10\"" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-dhcp6-discover.html;\
  ;broadcast-dhcp6-discover;--script=broadcast-dhcp6-discover -6" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-dns-service-discovery.html;\
  ;broadcast-dns-service-discovery;--script=broadcast-dns-service-discovery" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-dropbox-listener.html;\
  ;broadcast-dropbox-listener;--script=broadcast-dropbox-listener" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-eigrp-discovery.html;\
  ;broadcast-eigrp-discovery;--script=broadcast-eigrp-discovery;\
  \"broadcast-eigrp-discovery.kparams=101000\",\"broadcast-eigrp-discovery.as=224.0.0.10\",\
  \"broadcast-eigrp-discovery.interface\",\"broadcast-eigrp-discovery.timeout=10\"" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-igmp-discovery.html;\
  ;broadcast-igmp-discovery;--script=broadcast-igmp-discovery;\
  \"broadcast-igmp-discovery.mgroupnamesdb\",\"broadcast-igmp-discovery.version=2\",\
  \"broadcast-igmp-discovery.timeout=5\",\"broadcast-igmp-discovery.interface\"" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-listener.html;\
  ;broadcast-listener;--script=broadcast-listener;\
  \"broadcast-listener.timeout=30\"" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-ms-sql-discover.html;\
  ;broadcast-ms-sql-discover;--script=broadcast-ms-sql-discover" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-netbios-master-browser.html;\
  ;broadcast-netbios-master-browser;--script=broadcast-netbios-master-browser" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-novell-locate.html;\
  ;broadcast-novell-locate;--script=broadcast-novell-locate" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-ospf2-discover.html;\
  ;broadcast-ospf2-discover;--script=broadcast-ospf2-discover;\
  \"broadcast-ospf2-discover.md5_key\",\"broadcast-ospf2-discover.router_id=0.0.0.1\",\
  \"broadcast-ospf2-discover.timeout=10\",\"broadcast-ospf2-discover.interface\"" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-ping.html;\
  ;broadcast-ping;--script=broadcast-ping;\
  \"broadcast-ping.timeout=3\",\"broadcast-ping.num_probes=1\"\
  \"broadcast-ping.interface\"" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-pppoe-discover.html;\
  ;broadcast-pppoe-discover;--script=broadcast-pppoe-discover" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-rip-discover.html;\
  ;broadcast-rip-discover;--script=broadcast-rip-discover;\
  \"broadcast-rip-discover.timeout=5\"" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-ripng-discover.html;\
  ;broadcast-ripng-discover;--script=broadcast-ripng-discover;\
  \"broadcast-ripng-discover.timeout=5\"" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-upnp-info.html;\
  ;broadcast-upnp-info;--script=broadcast-upnp-info" \
  #
  "https://nmap.org/nsedoc/scripts/broadcast-db2-discover.html;\
  ;broadcast-wake-on-lan;--script=broadcast-wake-on-lan;\
  \"broadcast-wake-on-lan.address\",\"broadcast-wake-on-lan.MAC\"" \
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
