#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: http-protocol()
#
# Description:
#   HTTP Protocol Module.
#
# Usage:
#   http-protocol
#
# Examples:
#   http-protocol
#

function http-protocol() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="http-protocol"
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
  description="HTTP Protocol Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      HTTP Protocol Module.

    Commands
    --------

      help                            display module help
      show    <key>                   display module or profile info
      config  <key>                   show module configuration
      set     <key>                   set module variable value
      use     <module>                reuse module (changed env)
      pushd   <key>|init|show|flush   command line commands stack
      search  <key>                   search key in all commands

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
  "https://nmap.org/nsedoc/scripts/http-affiliate-id.html;\
  ;http-affiliate-id;--script=http-affiliate-id.nse $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-auth.html;\
  ;http-auth;--script http-auth $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-auth-finder.html;\
  ;http-auth-finder;--script http-auth-finder $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-backup-finder.html;\
  ;http-backup-finder;--script=http-backup-finder $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-brute.html;\
  ;http-brute;--script http-brute $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-chrono.html;\
  ;http-chrono;--script http-chrono $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-comments-displayer.html;\
  ;http-comments-displayer;--script http-comments-displayer $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-config-backup.html;\
  ;http-config-backup;--script=http-config-backup $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-cookie-flags.html;\
  ;http-cookie-flags;--script http-cookie-flags $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-cors.html;\
  ;http-cors;--script http-cors $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-cross-domain-policy.html;\
  ;http-cross-domain-policy;--script http-cross-domain-policy $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-csrf.html;\
  ;http-csrf;--script http-csrf $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-date.html;\
  ;http-date;--script=http-date $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-default-accounts.html;\
  ;http-default-accounts;--script http-default-accounts $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-devframework.html;\
  ;http-devframework;--script http-devframework $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-dlink-backdoor.html;\
  ;http-dlink-backdoor;--script http-dlink-backdoor $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-dombased-xss.html;\
  ;http-dombased-xss;--script http-dombased-xss $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-errors.html;\
  ;http-errors;--script http-errors $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-fileupload-exploiter.html;\
  ;http-fileupload-exploiter;--script http-fileupload-exploiter $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-form-brute.html;\
  ;http-form-brute;--script http-form-brute $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-form-fuzzer.html;\
  ;http-form-fuzzer;--script http-form-fuzzer $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-frontpage-login.html;\
  ;http-frontpage-login;--script=http-frontpage-login $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-grep.html;\
  ;http-grep;--script http-grep $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-headers.html;\
  ;http-headers;--script=http-headers $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-internal-ip-disclosure.html;\
  ;http-internal-ip-disclosure;--script http-internal-ip-disclosure $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-ls.html;\
  ;http-ls;--script http-ls $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-mcmp.html;\
  ;http-mcmp;--script=http-mcmp $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-method-tamper.html;\
  ;http-method-tamper;--script http-method-tamper $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-methods.html;\
  ;http-methods;--script http-methods $params" \
  #
  "https://nmap.org/nsedoc/scripts/http-open-proxy.html;\
  ;http-open-proxy;-script http-open-proxy $params" \
  #
  "https://nmap.org/nsedoc/scripts/amqp-info.html;\
  ;amqp-info;--script amqp-info $params" \
  #
  "https://nmap.org/nsedoc/scripts/amqp-info.html;\
  ;amqp-info;--script amqp-info $params" \
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
