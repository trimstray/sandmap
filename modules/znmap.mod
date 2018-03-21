#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: znmap()
#
# Description:
#   Sample module.
#
# Usage:
#   znmap
#
# Examples:
#   znmap
#

function znmap() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="znmap"
  local _STATE=0

  # User variables:
  # - module_name: store module name
  # - module_args: store module arguments

  _module_show=
  _module_help=

  # shellcheck disable=SC2034
  _module_variables=()

  # shellcheck disable=SC2034
  author="trimstray"
  contact="contact@nslab.at"
  version="1.0"
  category="zenmap"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_show=$(printf "%s" "
    Module: ${module_name}
    Author: ${author}
   Contact: ${contact}
   Version: ${version}
  Category: ${category}
")

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Zenmap predefined commands.

    Commands
    --------

      list                          display scanning list commands
      init     <value>              run predefined scanning command

      Options:

        <key>                       key value

    Examples
    --------

      init fast_scan                run 'fast_scan' scanning profile
")

  # shellcheck disable=SC2034
  export _module_opts=(\
  "$_module_show" \
  "$_module_help")

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

  # shellcheck disable=SC2034
  _module_commands=(\
  "Intense scan;'';intense;-T4 -A -v $dst" \
  "Intense scan plus UDP;'';intense_udp;-sS -sU -T4 -A -v $dst" \
  "Intense scan, all TCP ports;'';intense_all_tcp;-p 1-65535 -T4 -A -v $dst" \
  "Intense scan, no ping;'';intense_no_ping;-T4 -A -v -Pn $dst" \
  "Ping scan;'';ping_scan;-sn $dst" \
  "Quick scan;'';quick;-T4 -F $dst" \
  "Quick scan plus;'';quick_plus;-sV -T4 -O -F --version-light $dst" \
  "Quick traceroute;'';quick_trace;-sn --traceroute $dst" \
  "Regular scan;'';regular;$dst" \
  "Slow comprehensive scan;'';slow;-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script \"default or (discovery and safe)\" $dst" \
  )

  return $_STATE

}
