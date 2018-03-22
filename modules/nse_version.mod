#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_version()
#
# Description:
#   NSE Version category module.
#
# Usage:
#   nse_version
#
# Examples:
#   nse_version
#

function nse_version() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_version"
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
  description="NSE Version category module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE Version category module.

    Commands
    --------

      show                          display info about module
      list                          display scanning list profiles (commands)
      init     <value>              run predefined scanning command

      Options:

        <key>                       key value

    Examples
    --------

      init allseeingeye-info        Detects the All-Seeing Eye service
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
  "Detects the All-Seeing Eye service;'';allseeingeye-info;-Pn -sU -sV --script allseeingeye-info -p $port" \
  "Gathers information from an AMQP;'';amqp-info;--script amqp-info -p $port" \
  "Discovers and enumerates BACNet Devices;'';bacnet-info;--script bacnet-info -sU -p $port" \
  "Detects the CCcam service (port: 12000);'';cccam-version;-sV $port" \
  "Connects to the IBM DB2 (port: 523);'';db2-das-info;-sV $port" \
  "Detects the Docker service (port: 2375);'';docker-version;-sV $port"
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
