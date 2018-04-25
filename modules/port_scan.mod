#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: port_scan()
#
# Description:
#   Nmap Port Scan types module.
#
# Usage:
#   port_scan
#
# Examples:
#   port_scan
#

function port_scan() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="port_scan"
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
  description="Nmap Port Scan types module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      This section documents the dozen or so port scan techniques supported by
      Nmap. Only one method may be used at a time, except that UDP scan (-sU)
      and any one of the SCTP scan types (-sY, -sZ) may be combined with any one
      of the TCP scan types. As a memory aid, port scan type options are of the
      form -s<C>, where <C> is a prominent character in the scan name, usually
      the first. The one exception to this is the deprecated FTP bounce scan
      (-b). By default, Nmap performs a SYN Scan, though it substitutes a
      connect scan if the user does not have proper privileges to send raw
      packets (requires root access on Unix).

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

  # ---------------------------------------------------------------------------------------\n

  # shellcheck disable=SC2034
  _module_commands=(\
  #
  "https://nmap.org/book/man-port-scanning-techniques.html;\
  ;tcp_syn;-sS" \
  #
  "https://nmap.org/book/man-port-scanning-techniques.html;\
  ;tcp_conn;-sT" \
  #
  "https://nmap.org/book/man-port-scanning-techniques.html;\
  ;udp_scan;-sU" \
  #
  "https://nmap.org/book/man-port-scanning-techniques.html;\
  ;sctp_scan;-sY" \
  #
  "https://nmap.org/book/man-port-scanning-techniques.html;\
  ;null_scan;-sN" \
  #
  "https://nmap.org/book/man-port-scanning-techniques.html;\
  ;fin_scan;-sF" \
  #
  "https://nmap.org/book/man-port-scanning-techniques.html;\
  ;xmas_scan;-sX" \
  #
  "https://nmap.org/book/man-port-scanning-techniques.html;\
  ;tcp_ack_scan;-sA" \
  #
  "https://nmap.org/book/man-port-scanning-techniques.html;\
  ;tcp_window;-sW" \
  #
  "https://nmap.org/book/man-port-scanning-techniques.html;\
  ;tcp_maimon;-sM" \
  #
  "https://nmap.org/book/man-port-scanning-techniques.html;\
  ;ip_proto_scan;-sO" \
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
