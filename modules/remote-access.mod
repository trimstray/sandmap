#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: remote-access()
#
# Description:
#   Remote Access Module.
#
# Usage:
#   remote-access
#
# Examples:
#   remote-access
#

function remote-access() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="remote-access"
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
  description="Remote Access Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Remote Access Module.

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
  "https://nmap.org/nsedoc/scripts/rdp-enum-encryption.html;\
  ;rdp-enum-encryption;--script rdp-enum-encryption $params" \
  #
  "https://nmap.org/nsedoc/scripts/rdp-vuln-ms12-020.html;\
  ;rdp-vuln-ms12-020;--script rdp-vuln-ms12-020 $params" \
  #
  "https://nmap.org/nsedoc/scripts/realvnc-auth-bypass.html;\
  ;realvnc-auth-bypass;--script realvnc-auth-bypass $params" \
  #
  "https://nmap.org/nsedoc/scripts/vnc-brute.html;\
  ;vnc-brute;--script vnc-brute $params" \
  #
  "https://nmap.org/nsedoc/scripts/vnc-info.html;\
  ;vnc-info;--script vnc-info $params" \
  #
  "https://nmap.org/nsedoc/scripts/vnc-title.html;\
  ;vnc-title;--script vnc-title $params" \
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
