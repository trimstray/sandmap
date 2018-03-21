#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: service_os()
#
# Description:
#   Service and OS Detection module.
#
# Usage:
#   service_os
#
# Examples:
#   service_os
#

function service_os() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="service_os"
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
  category="services"

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

      Service and OS Detection module.

    Commands
    --------

      list                          display scanning list commands
      init     <value>              run predefined scanning command

      Options:

        <key>                       key value

    Examples
    --------

      init more_aggressive          run Aggressive Service Detection profile
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
  "Detect OS and Services;'';os_service;-A" \
  "Standard Service Detection;'';standard;-sV" \
  "Aggressive Service Detection;'';more_aggressive;-sV --version-intensity 5" \
  "Banner Grabbing Detection;'';banner;-sV --version-intensity 0" \
  )

  return $_STATE

}
