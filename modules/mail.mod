#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: mail()
#
# Description:
#   Mail Module.
#
# Usage:
#   mail
#
# Examples:
#   mail
#

function mail() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="mail"
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
  description="Mail Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Mail Module.

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
  "https://nmap.org/nsedoc/scripts/imap-brute.html;\
  ;imap-brute;--script imap-brute $params" \
  #
  "https://nmap.org/nsedoc/scripts/imap-capabilities.html;\
  ;imap-capabilities;--script imap-capabilities $params" \
  #
  "https://nmap.org/nsedoc/scripts/imap-ntlm-info.html;\
  ;imap-ntlm-info;--script imap-ntlm-info $params" \
  #
  "https://nmap.org/nsedoc/scripts/pop3-brute.html;\
  ;pop3-brute;--script pop3-brute $params" \
  #
  "https://nmap.org/nsedoc/scripts/pop3-capabilities.html;\
  ;pop3-capabilities;--script pop3-capabilities $params" \
  #
  "https://nmap.org/nsedoc/scripts/pop3-ntlm-info.html;\
  ;pop3-ntlm-info;--script pop3-ntlm-info $params" \
  #
  "https://nmap.org/nsedoc/scripts/smtp-brute.html;\
  ;smtp-brute;--script smtp-brute $params" \
  #
  "https://nmap.org/nsedoc/scripts/smtp-commands.html;\
  ;smtp-commands;--script smtp-commands $params" \
  #
  "https://nmap.org/nsedoc/scripts/smtp-enum-users.html;\
  ;smtp-enum-users;--script smtp-enum-users $params" \
  #
  "https://nmap.org/nsedoc/scripts/smtp-ntlm-info.html;\
  ;smtp-ntlm-info;--script smtp-ntlm-info $params" \
  #
  "https://nmap.org/nsedoc/scripts/smtp-open-relay.html;\
  ;smtp-open-relay;--script smtp-open-relay $params" \
  #
  "https://nmap.org/nsedoc/scripts/smtp-strangeport.html;\
  ;smtp-strangeport;--script smtp-strangeport $params" \
  #
  "https://nmap.org/nsedoc/scripts/smtp-vuln-cve2010-4344.html;\
  ;smtp-vuln-cve2010-4344;--script smtp-vuln-cve2010-4344 $params" \
  #
  "https://nmap.org/nsedoc/scripts/smtp-vuln-cve2011-1720.html;\
  ;smtp-vuln-cve2011-1720;--script smtp-vuln-cve2011-1720 $params" \
  #
  "https://nmap.org/nsedoc/scripts/smtp-vuln-cve2011-1764.html;\
  ;smtp-vuln-cve2011-1764;--script smtp-vuln-cve2011-1764 $params" \
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
