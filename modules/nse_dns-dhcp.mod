#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_dns-dhcp()
#
# Description:
#   NSE DNS and DHCP Module.
#
# Usage:
#   nse_dns-dhcp
#
# Examples:
#   nse_dns-dhcp
#

function nse_dns-dhcp() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_dns-dhcp"
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
  description="NSE DNS and DHCP Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE DNS and DHCP Module.

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
  "https://nmap.org/nsedoc/scripts/asn-query.html;\
  ;asn-query;--script asn-query $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-blacklist.html;\
  ;dns-blacklist;--script dns-blacklist $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-brute.html;\
  ;dns-brute;--script dns-brute $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-cache-snoop.html;\
  ;dns-cache-snoop;--script dns-cache-snoop.nse $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-check-zone.html;\
  ;dns-check-zone;--script dns-check-zone $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-client-subnet-scan.html;\
  ;dns-client-subnet-scan;--script dns-client-subnet-scan $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-fuzz.html;\
  ;dns-fuzz;--script dns-fuzz $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-ip6-arpa-scan.html;\
  ;dns-ip6-arpa-scan;--script dns-ip6-arpa-scan $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-nsec-enum.html;\
  ;dns-nsec-enum;--script dns-nsec-enum $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-nsec3-enum.html;\
  ;dns-nsec3-enum;--script=dns-nsec3-enum $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-nsid.html;\
  ;dns-nsid;--script dns-nsid $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-random-srcport.html;\
  ;dns-random-srcport;--script=dns-random-srcport $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-random-txid.html;\
  ;dns-random-txid;--script=dns-random-txid $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-recursion.html;\
  ;dns-recursion;--script=dns-recursion $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-service-discovery.html;\
  ;dns-service-discovery;--script=dns-service-discovery $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-srv-enum.html;\
  ;dns-srv-enum;--script dns-srv-enum $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-update.html;\
  ;dns-update;--script=dns-update $params" \
  #
  "https://nmap.org/nsedoc/scripts/dns-zone-transfer.html;\
  ;dns-zone-transfer;--script dns-zone-transfer.nse $params" \
  #
  "https://nmap.org/nsedoc/scripts/fcrdns.html;\
  ;fcrdns;--script fcrdns $params" \
  #
  "https://nmap.org/nsedoc/scripts/hostmap-bfk.html;\
  ;hostmap-bfk;--script hostmap-bfk $params" \
  #
  "https://nmap.org/nsedoc/scripts/hostmap-crtsh.html;\
  ;hostmap-crtsh;--script hostmap-crtsh $params" \
  #
  "https://nmap.org/nsedoc/scripts/hostmap-ip2hosts.html;\
  ;hostmap-ip2hosts;--script hostmap-ip2hosts $params" \
  #
  "https://nmap.org/nsedoc/scripts/hostmap-robtex.html;\
  ;hostmap-robtex;--script hostmap-robtex $params" \
  #
  "https://nmap.org/nsedoc/scripts/llmnr-resolve.html;\
  ;llmnr-resolve;--script llmnr-resolve $params" \
  #
  "https://nmap.org/nsedoc/scripts/dhcp-discover.html;\
  ;dhcp-discover;--script=dhcp-discover $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-robtex-reverse-ip.html;\
  ;http-robtex-reverse-ip;--script=http-robtex-reverse-ip $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-robtex-shared-ns.html;\
  ;http-robtex-shared-ns;--script=http-robtex-shared-ns $params" \
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
