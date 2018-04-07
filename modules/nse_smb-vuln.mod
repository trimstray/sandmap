#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_smb-vuln()
#
# Description:
#   NSE SMB Protocol Vulnerability Module.
#
# Usage:
#   nse_smb-vuln
#
# Examples:
#   nse_smb-vuln
#

function nse_smb-vuln() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_smb-vuln"
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
  description="NSE SMB Protocol Vulnerability Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE SMB Protocol Vulnerability Module.

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
  "https://nmap.org/nsedoc/scripts/samba-vuln-cve-2012-1182.html;\
  ;samba-vuln-cve-2012-1182;--script samba-vuln-cve-2012-1182 $params" \
  #
  "https://nmap.org/nsedoc/scripts/smb-vuln-conficker.html;\
  ;smb-vuln-conficker;--script smb-vuln-conficker $params" \
  #
  "https://nmap.org/nsedoc/scripts/smb-vuln-cve-2017-7494.html;\
  ;smb-vuln-cve-2017-7494;--script smb-vuln-cve-2017-7494 $params" \
  #
  "https://nmap.org/nsedoc/scripts/smb-vuln-cve2009-3103.html;\
  ;smb-vuln-cve2009-3103;--script smb-vuln-cve2009-3103 $params" \
  #
  "https://nmap.org/nsedoc/scripts/smb-vuln-ms06-025.html;\
  ;smb-vuln-ms06-025;--script smb-vuln-ms06-025 $params" \
  #
  "https://nmap.org/nsedoc/scripts/smb-vuln-ms07-029.html;\
  ;smb-vuln-ms07-029;--script smb-vuln-ms07-029 $params" \
  #
  "https://nmap.org/nsedoc/scripts/smb-vuln-ms08-067.html;\
  ;smb-vuln-ms08-067;--script smb-vuln-ms08-067 $params" \
  #
  "https://nmap.org/nsedoc/scripts/smb-vuln-ms10-054.html;\
  ;smb-vuln-ms10-054;--script smb-vuln-ms10-054 $params" \
  #
  "https://nmap.org/nsedoc/scripts/smb-vuln-ms10-061.html;\
  ;smb-vuln-ms10-061;--script smb-vuln-ms10-061 $params" \
  #
  "https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html;\
  ;smb-vuln-ms17-010;--script smb-vuln-ms17-010 $params" \
  #
  "https://nmap.org/nsedoc/scripts/smb-vuln-regsvc-dos.html;\
  ;smb-vuln-regsvc-dos;--script smb-vuln-regsvc-dos $params" \
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
