#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: sample()
#
# Description:
#   Sample module.
#
# Usage:
#   sample
#
# Examples:
#   sample
#

function sample() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="sample"
  local _STATE=0

  # User variables:
  # - module_name: store module name
  # - module_args: store module arguments

  _module_show=
  _module_help=

  # shellcheck disable=SC2034
  _module_variables=()

  # shellcheck disable=SC2034
  author="example"
  contact="example@example.com"
  version="1.0"
  category="scanning"

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

      It's a sample module template - short description.

    Commands
    --------

      list                          display scanning list commands
      init     <value>              run predefined scanning command

      Options:

        <key>                       key value

    Examples
    --------

      config dbpass                 show 'dbpass' module key value
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
      _module_variables=(\
      "Testing;'test1|test2';testing;testing_value")

      printf "_module_variables=(\"%s\")\n" "${_module_variables[@]}" > "$_module_cfg"

      _mstate=1

    fi

  else

    # shellcheck disable=SC1090
    source "$_module_cfg"

  fi

  # shellcheck disable=SC2034
  _module_commands=(\
  "Fast Scanning;;fast_scan;-sV -T4 -O -F $ipaddr" \
  "ACK Scanning;;ack_scan;-sA $ipaddr")

  return $_STATE

}
