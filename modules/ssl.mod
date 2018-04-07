#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: ssl()
#
# Description:
#   SSL Module.
#
# Usage:
#   ssl
#
# Examples:
#   ssl
#

function ssl() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="ssl"
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
  description="SSL Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      SSL Module.

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
  "https://nmap.org/nsedoc/scripts/rsa-vuln-roca.html;\
  ;rsa-vuln-roca;--script rsa-vuln-roca $params" \
  #
  "https://nmap.org/nsedoc/scripts/ssl-ccs-injection.html;\
  ;ssl-ccs-injection;--script ssl-ccs-injection $params" \
  #
  "https://nmap.org/nsedoc/scripts/ssl-cert-intaddr.html;\
  ;ssl-cert-intaddr;--script ssl-cert-intaddr $params" \
  #
  "https://nmap.org/nsedoc/scripts/ssl-cert.html;\
  ;ssl-cert;--script ssl-cert $params" \
  #
  "https://nmap.org/nsedoc/scripts/ssl-date.html;\
  ;ssl-date;--script ssl-date $params" \
  #
  "https://nmap.org/nsedoc/scripts/ssl-dh-params.html;\
  ;ssl-dh-params;--script ssl-dh-params $params" \
  #
  "https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html;\
  ;ssl-enum-ciphers;--script ssl-enum-ciphers $params" \
  #
  "https://nmap.org/nsedoc/scripts/ssl-heartbleed.html;\
  ;ssl-heartbleed;--script ssl-heartbleed $params" \
  #
  "https://nmap.org/nsedoc/scripts/ssl-known-key.html;\
  ;ssl-known-key;--script ssl-known-key $params" \
  #
  "https://nmap.org/nsedoc/scripts/ssl-poodle.html;\
  ;ssl-poodle;--script ssl-poodle $params" \
  #
  "https://nmap.org/nsedoc/scripts/sslv2-drown.html;\
  ;sslv2-drown;--script sslv2-drown $params" \
  #
  "https://nmap.org/nsedoc/scripts/sslv2.html;\
  ;sslv2;--script sslv2 $params" \
  #
  "https://nmap.org/nsedoc/scripts/sstp-discover.html;\
  ;sstp-discover;--script sstp-discover $params" \
  #
  "https://nmap.org/nsedoc/scripts/tls-alpn.html;\
  ;tls-alpn;--script tls-alpn $params" \
  #
  "https://nmap.org/nsedoc/scripts/tls-nextprotoneg.html;\
  ;tls-nextprotoneg;--script tls-nextprotoneg $params" \
  #
  "https://nmap.org/nsedoc/scripts/tls-ticketbleed.html;\
  ;tls-ticketbleed;--script tls-ticketbleed $params" \
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
