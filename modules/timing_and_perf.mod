#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: timing_and_perf()
#
# Description:
#   Timing and Performance module.
#
# Usage:
#   timing_and_perf
#
# Examples:
#   timing_and_perf
#

function timing_and_perf() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="timing_and_perf"
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
  description="Timing and Performance module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Nmap Host Discovery module.

    Commands
    --------

      show                          display info about module
      list                          display scanning list profiles (commands)
      init     <value>              run predefined scanning command

      Options:

        <key>                       key value

    Examples
    --------

      init t1                       Sneaky (1) Intrusion Detection System evasion.
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
  "Paranoid (0) Intrusion Detection System evasion;\
  ;t0;-T0" \
  #
  "Sneaky (1) Intrusion Detection System evasion;\
  ;t1;-T1" \
  #
  "Polite (2) Slows down the scan;\
  ;t2;-T2" \
  #
  "Normal (3) Which is default speed;\
  ;t3;-T3" \
  #
  "Aggressive (4) If you are on a fast and reliable network;\
  ;t4;-T4" \
  #
  "Insane (5) If you are on an extraordinarily fast network;\
  ;t5;-T5" \
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
