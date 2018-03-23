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
  contact="contact@nslab.at"
  version="1.0"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Nmap Port Scan types module.

    Commands
    --------

      show                          display info about module
      list                          display scanning list profiles (commands)
      init     <value>              run predefined scanning command

      Options:

        <key>                       key value

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
  "TCP connect;\
  ;tcp_conn;-sT" \
  #
  "TCP SYN scan;\
  ;tcp_syn;-sS" \
  #
  "TCP ACK port scan;\
  ;tcp_ack;-sA" \
  #
  "TCP Window port scan;\
  ;tcp_window;-sW" \
  #
  "TCP Maimon port scan;\
  ;tcp_maimon;-sU" \
  #
  "UDP ports scan;\
  ;udp;-sM" \
  #
  "Fast port scan (100 ports);\
  ;fast;-F" \
  #
  "Ports and ignore discovery;\
  ;ports_not_disc;-Pn -F" \
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
