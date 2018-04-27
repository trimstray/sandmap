#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: host_discovery()
#
# Description:
#   Nmap Host Discovery module.
#
# Usage:
#   host_discovery
#
# Examples:
#   host_discovery
#

function host_discovery() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="host_discovery"
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
  description="Nmap Host Discovery module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Nmap does host discovery and then performs a port
      scan against each host it determines is online.

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

  # ---------------------------------------------------------------------------------------\n

  # shellcheck disable=SC2034
  _module_commands=(\
  #
  "https://nmap.org/book/man-host-discovery.html;\
  ;list_scan;-sL" \
  #
  "https://nmap.org/book/man-host-discovery.html;\
  ;ping_scan;-sP" \
  #
  "https://nmap.org/book/man-host-discovery.html;\
  ;no_port_scan;-sn" \
  #
  "https://nmap.org/book/man-host-discovery.html;\
  ;no_ping;-Pn" \
  #
  "https://nmap.org/book/man-host-discovery.html;\
  ;tcp_syn_ping;-PS" \
  #
  "https://nmap.org/book/man-host-discovery.html;\
  ;tcp_ack_ping;-PA" \
  #
  "https://nmap.org/book/man-host-discovery.html;\
  ;udp_ping;-PU" \
  #
  "https://nmap.org/book/man-host-discovery.html;\
  ;sctp_init_ping;-PY" \
  #
  "https://nmap.org/book/man-host-discovery.html;\
  ;arp_ping;-PR" \
  #
  "https://nmap.org/book/man-host-discovery.html;\
  ;icmp_ping-1;-PE" \
  #
  "https://nmap.org/book/man-host-discovery.html;\
  ;icmp_ping-2;-PP" \
  #
  "https://nmap.org/book/man-host-discovery.html;\
  ;icmp_ping-3;-PM" \
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
