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
  description="NSE DNS and DHCP Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s: \\e[1;32m%s\\e[m" "
  Module" "${module_name}")

  _module_help+=$(printf "%s" "

    Description
    -----------

      NSE DNS and DHCP Module.

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
  "https://nmap.org/nsedoc/scripts/asn-query.html;\
  ;asn-query;--script=asn-query;\
  \"dns\"" \
  #
  "https://nmap.org/nsedoc/scripts/dns-blacklist.html;\
  ;dns-blacklist;--script=dns-blacklist;\
  \"dns-blacklist.services=all\",\"dns-blacklist.ip\",\
  \"dns-blacklist.list\",\"dns-blacklist.category=all\",\
  \"dns-blacklist.mode=long\"" \
  #
  "https://nmap.org/nsedoc/scripts/dns-brute.html;\
  ;dns-brute;--script=dns-brute;\
  \"dns-brute.threads=5\",\"dns-brute.srvlist=nselib/data/dns-srv-names\",\
  \"dns-brute.hostlist=nselib/data/vhosts-default.lst\",\"dns-brute.srv\",\
  \"dns-brute.domain\"" \
  #
  "https://nmap.org/nsedoc/scripts/dns-cache-snoop.html;\
  ;dns-cache-snoop;--script=dns-cache-snoop.nse;\
  \"dns-cache-snoop.mode=nonrecursive\",\"dns-cache-snoop.domains\"" \
  #
  "https://nmap.org/nsedoc/scripts/dns-check-zone.html;\
  ;dns-check-zone;--script=dns-check-zone;\
  \"dns-check-zone.domain\"" \
  #
  "https://nmap.org/nsedoc/scripts/dns-client-subnet-scan.html;\
  ;dns-client-subnet-scan;--script=dns-client-subnet-scan;\
  \"dns-client-subnet-scan.domain\",\"dns-client-subnet-scan.mask=24\",\
  \"dns-client-subnet-scan.nameserver=host.ip\",\"dns-client-subnet-scan.address\"" \
  #
  "https://nmap.org/nsedoc/scripts/dns-fuzz.html;\
  ;dns-fuzz;--script=dns-fuzz;\
  \"dns-fuzz.timelimit=10m\"" \
  #
  "https://nmap.org/nsedoc/scripts/dns-ip6-arpa-scan.html;\
  ;dns-ip6-arpa-scan;--script=dns-ip6-arpa-scan;\
  \"prefix\",\"mask\"" \
  #
  "https://nmap.org/nsedoc/scripts/dns-nsec-enum.html;\
  ;dns-nsec-enum;--script=dns-nsec-enum;\
  \"dns-nsec-enum.domains\"" \
  #
  "https://nmap.org/nsedoc/scripts/dns-nsec3-enum.html;\
  ;dns-nsec3-enum;--script=dns-nsec3-enum;\
  \"dns-nsec3-enum.domains\",\"dns-nsec3-enum.timelimit=30m\"" \
  #
  "https://nmap.org/nsedoc/scripts/dns-nsid.html;\
  ;dns-nsid;--script=dns-nsid" \
  #
  "https://nmap.org/nsedoc/scripts/dns-random-srcport.html;\
  ;dns-random-srcport;--script=dns-random-srcport" \
  #
  "https://nmap.org/nsedoc/scripts/dns-random-txid.html;\
  ;dns-random-txid;--script=dns-random-txid" \
  #
  "https://nmap.org/nsedoc/scripts/dns-recursion.html;\
  ;dns-recursion;--script=dns-recursion" \
  #
  "https://nmap.org/nsedoc/scripts/dns-service-discovery.html;\
  ;dns-service-discovery;--script=dns-service-discovery" \
  #
  "https://nmap.org/nsedoc/scripts/dns-srv-enum.html;\
  ;dns-srv-enum;--script=dns-srv-enum;\
  \"dns-srv-enum.domain\",\"dns-srv-enum.filter=all\"" \
  #
  "https://nmap.org/nsedoc/scripts/dns-update.html;\
  ;dns-update;--script=dns-update;\
  \"dns-update.test\",\"dns-update.ip\",\"dns-update.hostname\"" \
  #
  "https://nmap.org/nsedoc/scripts/dns-zone-transfer.html;\
  ;dns-zone-transfer;--script=dns-zone-transfer;\
  \"dns-zone-transfer.port=53\",\"dns-zone-transfer.server\",\
  \"dns-zone-transfer.domain\"" \
  #
  "https://nmap.org/nsedoc/scripts/fcrdns.html;\
  ;fcrdns;--script=fcrdns" \
  #
  "https://nmap.org/nsedoc/scripts/hostmap-bfk.html;\
  ;hostmap-bfk;--script=hostmap-bfk;\
  \"hostmap-bfk.prefix\"" \
  #
  "https://nmap.org/nsedoc/scripts/hostmap-crtsh.html;\
  ;hostmap-crtsh;--script=hostmap-crtsh;\
  \"hostmap.prefix\"" \
  #
  "https://nmap.org/nsedoc/scripts/hostmap-ip2hosts.html;\
  ;hostmap-ip2hosts;--script=hostmap-ip2hosts;\
  \"hostmap.prefix\"" \
  #
  "https://nmap.org/nsedoc/scripts/hostmap-robtex.html;\
  ;hostmap-robtex;--script=hostmap-robtex" \
  #
  "https://nmap.org/nsedoc/scripts/llmnr-resolve.html;\
  ;llmnr-resolve;--script=llmnr-resolve;\
  \"llmnr-resolve.timeout=3s\",\"llmnr-resolve.hostname\"" \
  #
  "https://nmap.org/nsedoc/scripts/dhcp-discover.html;\
  ;dhcp-discover;--script=dhcp-discover;\
  \"randomize_mac\",\"requests\",\"dhcptype=DHCPINFORM\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-robtex-reverse-ip.html;\
  ;http-robtex-reverse-ip;--script=http-robtex-reverse-ip;\
  \"http-robtex-reverse-ip.host\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-robtex-shared-ns.html;\
  ;http-robtex-shared-ns;--script=http-robtex-shared-ns" \
  )

  # shellcheck disable=SC2034,SC2154
  _module_show=(\
      "${module_name}" \
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
