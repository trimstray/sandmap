#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_external()
#
# Description:
#   NSE external scripts.
#
# Usage:
#   nse_external
#
# Examples:
#   nse_external
#

function nse_external() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_external"
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
  description="NSE external scripts"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE external scripts.

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

  # shellcheck disable=SC2034
  _module_commands=(\
  #
  "https://github.com/vulnersCom/nmap-vulners;\
  ;vulners-script;--script=${_nse}/vulners/vulners.nse" \
  #
  "https://github.com/scipag/vulscan;\
  ;vulscan-script;--script=${_nse}/vulscan/vulscan.nse" \
  #
  "https://github.com/s4n7h0/NSE;\
  ;http-nikto-scan;--script=${_nse}/s4n7h0/http-nikto-scan.nse" \
  #
  "https://github.com/s4n7h0/NSE;\
  ;http-shellshock;--script=${_nse}/s4n7h0/http-shellshock.nse" \
  #
  "https://github.com/scipag/httprecon-nse;\
  ;httprecon-nse;--script=${_nse}/httprecon-nse/httprecon.nse" \
  #
  "https://github.com/michenriksen/nmap-scripts;\
  ;http-apache-server-status;--script=${_nse}/michenriksen/http-apache-server-status.nse" \
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
