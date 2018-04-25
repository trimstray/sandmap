#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_ftp()
#
# Description:
#   NSE FTP Service Module.
#
# Usage:
#   nse_ftp
#
# Examples:
#   nse_ftp
#

function nse_ftp() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_ftp"
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
  description="NSE FTP Service Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE FTP Service Module.

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
  "https://nmap.org/nsedoc/scripts/ftp-anon.html;\
  ;ftp-anon;--script=ftp-anon" \
  #
  "https://nmap.org/nsedoc/scripts/ftp-bounce.html;\
  ;ftp-bounce;--script=ftp-bounce" \
  #
  "https://nmap.org/nsedoc/scripts/ftp-brute.html;\
  ;ftp-brute;--script=ftp-brute" \
  #
  "https://nmap.org/nsedoc/scripts/ftp-libopie.html;\
  ;ftp-libopie;--script=ftp-libopie" \
  #
  "https://nmap.org/nsedoc/scripts/ftp-proftpd-backdoor.html;\
  ;ftp-proftpd-backdoor;--script=ftp-proftpd-backdoor" \
  #
  "https://nmap.org/nsedoc/scripts/ftp-syst.html;\
  ;ftp-syst;--script=ftp-syst" \
  #
  "https://nmap.org/nsedoc/scripts/ftp-vsftpd-backdoor.html;\
  ;ftp-vsftpd-backdoor;--script=ftp-vsftpd-backdoor" \
  #
  "https://nmap.org/nsedoc/scripts/ftp-vuln-cve2010-4221.html;\
  ;ftp-vuln-cve2010-4221;--script=ftp-vuln-cve2010-4221" \
  #
  "https://nmap.org/nsedoc/scripts/tftp-enum.html;\
  ;tftp-enum;--script=tftp-enum" \
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
