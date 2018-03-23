#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: znmap()
#
# Description:
#   Zenmap module.
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
  description="Zenmap module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Zenmap predefined commands.

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
  "Intense scan;\
  ;intense;-T4 -A -v" \
  #
  "Intense scan plus UDP;\
  ;intense_udp;-sS -sU -T4 -A -v" \
  #
  "Intense scan, all TCP ports;\
  ;intense_all_tcp;-p 1-65535 -T4 -A -v" \
  #
  "Intense scan, no ping;\
  ;intense_no_ping;-T4 -A -v -Pn" \
  #
  "Ping scan;\
  ;ping_scan;-sn" \
  #
  "Quick scan;\
  ;quick;-T4 -F" \
  #
  "Quick scan plus;\
  ;quick_plus;-sV -T4 -O -F --version-light" \
  #
  "Quick traceroute;\
  ;quick_trace;-sn --traceroute" \
  #
  "Regular scan;\
  ;regular;" \
  #
  "Slow comprehensive scan;\
  ;slow;-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script \"default or (discovery and safe)\"" \
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
