#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_other-network()
#
# Description:
#   NSE Other Network Module.
#
# Usage:
#   nse_other-network
#
# Examples:
#   nse_other-network
#

function nse_other-network() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_other-network"
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
  description="NSE Other Network Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE Other Network Module.

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
  "https://nmap.org/nsedoc/scripts/address-info.html;\
  ;address-info;--script=address-info" \
  #
  "https://nmap.org/nsedoc/scripts/firewall-bypass.html;\
  ;firewall-bypass;--script=firewall-bypass" \
  #
  "https://nmap.org/nsedoc/scripts/ip-forwarding.html;\
  ;ip-forwarding;--script=ip-forwarding" \
  #
  "https://nmap.org/nsedoc/scripts/ip-geolocation-geoplugin.html;\
  ;ip-geolocation-geoplugin;--script=ip-geolocation-geoplugin" \
  #
  "https://nmap.org/nsedoc/scripts/ip-geolocation-ipinfodb.html;\
  ;ip-geolocation-ipinfodb;--script=ip-geolocation-ipinfodb" \
  #
  "https://nmap.org/nsedoc/scripts/ip-geolocation-map-bing.html;\
  ;ip-geolocation-map-bing;--script=ip-geolocation-map-bing" \
  #
  "https://nmap.org/nsedoc/scripts/ip-geolocation-map-google.html;\
  ;ip-geolocation-map-google;--script=ip-geolocation-map-google" \
  #
  "https://nmap.org/nsedoc/scripts/ip-geolocation-map-kml.html;\
  ;ip-geolocation-map-kml;--script=ip-geolocation-map-kml" \
  #
  "https://nmap.org/nsedoc/scripts/ip-geolocation-maxmind.html;\
  ;ip-geolocation-maxmind;--script=ip-geolocation-maxmind" \
  #
  "https://nmap.org/nsedoc/scripts/ip-https-discover.html;\
  ;ip-https-discover;--script=ip-https-discover" \
  #
  "https://nmap.org/nsedoc/scripts/ipv6-multicast-mld-list.html;\
  ;ipv6-multicast-mld-list;--script=ipv6-multicast-mld-list" \
  #
  "https://nmap.org/nsedoc/scripts/ipv6-node-info.html;\
  ;ipv6-node-info;--script=ipv6-node-info" \
  #
  "https://nmap.org/nsedoc/scripts/ipv6-ra-flood.html;\
  ;ipv6-ra-flood;--script=ipv6-ra-flood" \
  #
  "https://nmap.org/nsedoc/scripts/mrinfo.html;\
  ;mrinfo;--script=mrinfo" \
  #
  "https://nmap.org/nsedoc/scripts/mtrace.html;\
  ;mtrace;--script=mtrace" \
  #
  "https://nmap.org/nsedoc/scripts/nat-pmp-info.html;\
  ;nat-pmp-info;--script=nat-pmp-info" \
  #
  "https://nmap.org/nsedoc/scripts/nat-pmp-mapport.html;\
  ;nat-pmp-mapport;--script=nat-pmp-mapport" \
  #
  "https://nmap.org/nsedoc/scripts/nbstat.html;\
  ;nbstat;--script=nbstat" \
  #
  "https://nmap.org/nsedoc/scripts/nping-brute.html;\
  ;nping-brute;--script=nping-brute" \
  #
  "https://nmap.org/nsedoc/scripts/path-mtu.html;\
  ;path-mtu;--script=path-mtu" \
  #
  "https://nmap.org/nsedoc/scripts/pptp-version.html;\
  ;pptp-version;--script=pptp-version" \
  #
  "https://nmap.org/nsedoc/scripts/qscan.html;\
  ;qscan;--script=qscan" \
  #
  "https://nmap.org/nsedoc/scripts/reverse-index.html;\
  ;reverse-index;--script=reverse-index" \
  #
  "https://nmap.org/nsedoc/scripts/sniffer-detect.html;\
  ;sniffer-detect;--script=sniffer-detect" \
  #
  "https://nmap.org/nsedoc/scripts/stun-info.html;\
  ;stun-info;--script=stun-info" \
  #
  "https://nmap.org/nsedoc/scripts/stun-version.html;\
  ;stun-version;--script=stun-version" \
  #
  "https://nmap.org/nsedoc/scripts/targets-asn.html;\
  ;targets-asn;--script=targets-asn" \
  #
  "https://nmap.org/nsedoc/scripts/targets-ipv6-map4to6.html;\
  ;targets-ipv6-map4to6;--script=targets-ipv6-map4to6" \
  #
  "https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-echo.html;\
  ;targets-ipv6-multicast-echo;--script=targets-ipv6-multicast-echo" \
  #
  "https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-invalid-dst.html;\
  ;targets-ipv6-multicast-invalid-dst;--script=targets-ipv6-multicast-invalid-dst" \
  #
  "https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-mld.html;\
  ;targets-ipv6-multicast-mld;--script=targets-ipv6-multicast-mld" \
  #
  "https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-slaac.html;\
  ;targets-ipv6-multicast-slaac;--script=targets-ipv6-multicast-slaac" \
  #
  "https://nmap.org/nsedoc/scripts/targets-ipv6-wordlist.html;\
  ;targets-ipv6-wordlist;--script=targets-ipv6-wordlist" \
  #
  "https://nmap.org/nsedoc/scripts/targets-sniffer.html;\
  ;targets-sniffer;--script=targets-sniffer" \
  #
  "https://nmap.org/nsedoc/scripts/targets-traceroute.html;\
  ;targets-traceroute;--script=targets-traceroute" \
  #
  "https://nmap.org/nsedoc/scripts/targets-xml.html;\
  ;targets-xml;--script=targets-xml" \
  #
  "https://nmap.org/nsedoc/scripts/tor-consensus-checker.html;\
  ;tor-consensus-checker;--script=tor-consensus-checker" \
  #
  "https://nmap.org/nsedoc/scripts/traceroute-geolocation.html;\
  ;traceroute-geolocation;--script=traceroute-geolocation" \
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
