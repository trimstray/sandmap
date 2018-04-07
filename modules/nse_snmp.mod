#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_snmp()
#
# Description:
#   NSE SNMP Protocol Module.
#
# Usage:
#   nse_snmp
#
# Examples:
#   nse_snmp
#

function nse_snmp() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_snmp"
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
  description="NSE SNMP Protocol Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE SNMP Protocol Module.

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
  "https://nmap.org/nsedoc/scripts/snmp-brute.html;\
  ;snmp-brute;--script snmp-brute" \
  #
  "https://nmap.org/nsedoc/scripts/snmp-hh3c-logins.html;\
  ;snmp-hh3c-logins;--script snmp-hh3c-logins" \
  #
  "https://nmap.org/nsedoc/scripts/snmp-info.html;\
  ;snmp-info;--script snmp-info" \
  #
  "https://nmap.org/nsedoc/scripts/snmp-interfaces.html;\
  ;snmp-interfaces;--script snmp-interfaces" \
  #
  "https://nmap.org/nsedoc/scripts/snmp-ios-config.html;\
  ;snmp-ios-config;--script snmp-ios-config" \
  #
  "https://nmap.org/nsedoc/scripts/snmp-netstat.html;\
  ;snmp-netstat;--script snmp-netstat" \
  #
  "https://nmap.org/nsedoc/scripts/snmp-processes.html;\
  ;snmp-processes;--script snmp-processes" \
  #
  "https://nmap.org/nsedoc/scripts/snmp-sysdescr.html;\
  ;snmp-sysdescr;--script snmp-sysdescr" \
  #
  "https://nmap.org/nsedoc/scripts/snmp-win32-services.html;\
  ;snmp-win32-services;--script snmp-win32-services" \
  #
  "https://nmap.org/nsedoc/scripts/snmp-win32-shares.html;\
  ;snmp-win32-shares;--script snmp-win32-shares" \
  #
  "https://nmap.org/nsedoc/scripts/snmp-win32-software.html;\
  ;snmp-win32-software;--script snmp-win32-software" \
  #
  "https://nmap.org/nsedoc/scripts/snmp-win32-users.html;\
  ;snmp-win32-users;--script snmp-win32-users" \
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
