#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_vuln()
#
# Description:
#   NSE Vuln category module.
#
# Usage:
#   nse_vuln
#
# Examples:
#   nse_vuln
#

function nse_vuln() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_vuln"
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
  description="NSE Vuln category module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE Vuln category module.

    Commands
    --------

      help                          display module help
      show    <key>                 display module or profile info
      config  <key>                 show module configuration
      set     <key>                 set module variable value
      init    <value>               run predefined scanning command

      Options:

        <key>                       key value
        <value>                     profile alias or id

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
  "Mac OS X AFP directory traversal, CVE-2010-0533;\
  -p 548;afp-path-vuln;-sV --script=afp-path-vuln -p 548" \
  #
  "Discover hosts using DNS and NULL UDP packet, CVE-2011-1002;\
  ;broadcast-avahi-dos;--script=broadcast-avahi-dos" \
  #
  "Exploits ClamAV servers to unauth comand execution (1);\
  ;clamav-exec-1;-sV --script clamav-exec" \
  #
  "Exploits ClamAV servers to unauth comand execution (2);\
  ;clamav-exec-2;--script clamav-exec --script-args cmd='scan',scandb='files.txt'" \
  #
  "Exploits ClamAV servers to unauth comand execution (3);\
  ;clamav-exec-3;--script clamav-exec --script-args cmd='shutdown'" \
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
