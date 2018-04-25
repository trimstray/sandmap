#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_oracle()
#
# Description:
#   NSE Oracle Services Module.
#
# Usage:
#   nse_oracle
#
# Examples:
#   nse_oracle
#

function nse_oracle() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_oracle"
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
  description="NSE Oracle Services Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE Oracle Services Module.

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
  "https://nmap.org/nsedoc/scripts/oracle-brute-stealth.html;\
  ;oracle-brute-stealth;--script=oracle-brute-stealth" \
  #
  "https://nmap.org/nsedoc/scripts/oracle-brute.html;\
  ;oracle-brute;--script=oracle-brute" \
  #
  "https://nmap.org/nsedoc/scripts/oracle-enum-users.html;\
  ;oracle-enum-users;--script=oracle-enum-users" \
  #
  "https://nmap.org/nsedoc/scripts/oracle-sid-brute.html;\
  ;oracle-sid-brute;--script=oracle-sid-brute" \
  #
  "https://nmap.org/nsedoc/scripts/oracle-tns-version.html;\
  ;oracle-tns-version;--script=oracle-tns-version" \
  #
  "https://nmap.org/nsedoc/scripts/ovs-agent-version.html;\
  ;ovs-agent-version;--script=ovs-agent-version" \
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
