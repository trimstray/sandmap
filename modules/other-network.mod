#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: other-network()
#
# Description:
#   Other Network Module.
#
# Usage:
#   other-network
#
# Examples:
#   other-network
#

function other-network() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="other-network"
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
  description="Other Network Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Other Network Module.

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
  "https://nmap.org/nsedoc/scripts/address-info.html;\
  ;address-info;--script address-info $params" \
  #
  "https://nmap.org/nsedoc/scripts/ip-forwarding.html;\
  ;ip-forwarding;--script ip-forwarding $params" \
  #
  "https://nmap.org/nsedoc/scripts/ip-https-discover.html;\
  ;ip-https-discover;--script ip-https-discover $params" \
  #
  "https://nmap.org/nsedoc/scripts/mrinfo.html;\
  ;mrinfo;--script mrinfo $params" \
  #
  "https://nmap.org/nsedoc/scripts/mtrace.html;\
  ;mtrace;--script mtrace $params" \
  #
  "https://nmap.org/nsedoc/scripts/nat-pmp-info.html;\
  ;nat-pmp-info;--script nat-pmp-info $params" \
  #
  "https://nmap.org/nsedoc/scripts/nat-pmp-mapport.html;\
  ;nat-pmp-mapport;--script nat-pmp-mapport $params" \
  #
  "https://nmap.org/nsedoc/scripts/nbstat.html;\
  ;nbstat;--script nbstat $params" \
  #
  "https://nmap.org/nsedoc/scripts/nping-brute.html;\
  ;nping-brute;--script nping-brute $params" \
  #
  "https://nmap.org/nsedoc/scripts/path-mtu.html;\
  ;path-mtu;--script path-mtu $params" \
  #
  "https://nmap.org/nsedoc/scripts/pptp-version.html;\
  ;pptp-version;--script pptp-version $params" \
  #
  "https://nmap.org/nsedoc/scripts/qscan.html;\
  ;qscan;--script qscan $params" \
  #
  "https://nmap.org/nsedoc/scripts/sniffer-detect.html;\
  ;sniffer-detect;--script sniffer-detect $params" \
  #
  "https://nmap.org/nsedoc/scripts/stun-info.html;\
  ;stun-info;--script stun-info $params" \
  #
  "https://nmap.org/nsedoc/scripts/stun-version.html;\
  ;stun-version;--script stun-version $params" \
  #
  "https://nmap.org/nsedoc/scripts/targets-asn.html;\
  ;targets-asn;--script targets-asn $params" \
  #
  "https://nmap.org/nsedoc/scripts/targets-sniffer.html;\
  ;targets-sniffer;--script targets-sniffer $params" \
  #
  "https://nmap.org/nsedoc/scripts/targets-traceroute.html;\
  ;targets-traceroute;--script targets-traceroute $params" \
  #
  "https://nmap.org/nsedoc/scripts/targets-xml.html;\
  ;targets-xml;--script targets-xml $params" \
  #
  "https://nmap.org/nsedoc/scripts/tor-consensus-checker.html;\
  ;tor-consensus-checker;--script tor-consensus-checker $params" \
  #
  "https://nmap.org/nsedoc/scripts/traceroute-geolocation.html;\
  ;traceroute-geolocation;--script traceroute-geolocation $params" \
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
