#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_http-protocol()
#
# Description:
#   NSE HTTP Protocol Module.
#
# Usage:
#   nse_http-protocol
#
# Examples:
#   nse_http-protocol
#

function nse_http-protocol() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_http-protocol"
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
  description="NSE HTTP Protocol Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE HTTP Protocol Module.

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
  "https://nmap.org/nsedoc/scripts/http-affiliate-id.html;\
  ;http-affiliate-id;--script=http-affiliate-id.nse" \
  #
  "https://nmap.org/nsedoc/scripts/http-auth.html;\
  ;http-auth;--script http-auth" \
  #
  "https://nmap.org/nsedoc/scripts/http-auth-finder.html;\
  ;http-auth-finder;--script http-auth-finder" \
  #
  "https://nmap.org/nsedoc/scripts/http-backup-finder.html;\
  ;http-backup-finder;--script=http-backup-finder" \
  #
  "https://nmap.org/nsedoc/scripts/http-brute.html;\
  ;http-brute;--script http-brute" \
  #
  "https://nmap.org/nsedoc/scripts/http-chrono.html;\
  ;http-chrono;--script http-chrono" \
  #
  "https://nmap.org/nsedoc/scripts/http-comments-displayer.html;\
  ;http-comments-displayer;--script http-comments-displayer" \
  #
  "https://nmap.org/nsedoc/scripts/http-config-backup.html;\
  ;http-config-backup;--script=http-config-backup" \
  #
  "https://nmap.org/nsedoc/scripts/http-cookie-flags.html;\
  ;http-cookie-flags;--script http-cookie-flags" \
  #
  "https://nmap.org/nsedoc/scripts/http-cors.html;\
  ;http-cors;--script http-cors" \
  #
  "https://nmap.org/nsedoc/scripts/http-cross-domain-policy.html;\
  ;http-cross-domain-policy;--script http-cross-domain-policy" \
  #
  "https://nmap.org/nsedoc/scripts/http-csrf.html;\
  ;http-csrf;--script http-csrf" \
  #
  "https://nmap.org/nsedoc/scripts/http-date.html;\
  ;http-date;--script=http-date" \
  #
  "https://nmap.org/nsedoc/scripts/http-default-accounts.html;\
  ;http-default-accounts;--script http-default-accounts" \
  #
  "https://nmap.org/nsedoc/scripts/http-devframework.html;\
  ;http-devframework;--script http-devframework" \
  #
  "https://nmap.org/nsedoc/scripts/http-dombased-xss.html;\
  ;http-dombased-xss;--script http-dombased-xss" \
  #
  "https://nmap.org/nsedoc/scripts/http-errors.html;\
  ;http-errors;--script http-errors" \
  #
  "https://nmap.org/nsedoc/scripts/http-fileupload-exploiter.html;\
  ;http-fileupload-exploiter;--script http-fileupload-exploiter" \
  #
  "https://nmap.org/nsedoc/scripts/http-form-brute.html;\
  ;http-form-brute;--script http-form-brute" \
  #
  "https://nmap.org/nsedoc/scripts/http-form-fuzzer.html;\
  ;http-form-fuzzer;--script http-form-fuzzer" \
  #
  "https://nmap.org/nsedoc/scripts/http-frontpage-login.html;\
  ;http-frontpage-login;--script=http-frontpage-login" \
  #
  "https://nmap.org/nsedoc/scripts/http-grep.html;\
  ;http-grep;--script http-grep" \
  #
  "https://nmap.org/nsedoc/scripts/http-headers.html;\
  ;http-headers;--script=http-headers" \
  #
  "https://nmap.org/nsedoc/scripts/http-internal-ip-disclosure.html;\
  ;http-internal-ip-disclosure;--script http-internal-ip-disclosure" \
  #
  "https://nmap.org/nsedoc/scripts/http-ls.html;\
  ;http-ls;--script http-ls" \
  #
  "https://nmap.org/nsedoc/scripts/http-mcmp.html;\
  ;http-mcmp;--script=http-mcmp" \
  #
  "https://nmap.org/nsedoc/scripts/http-method-tamper.html;\
  ;http-method-tamper;--script http-method-tamper" \
  #
  "https://nmap.org/nsedoc/scripts/http-methods.html;\
  ;http-methods;--script http-methods" \
  #
  "https://nmap.org/nsedoc/scripts/http-open-proxy.html;\
  ;http-open-proxy;--script http-open-proxy" \
  #
  "https://nmap.org/nsedoc/scripts/http-open-redirect.html;\
  ;http-open-redirect;--script=http-open-redirect" \
  #
  "https://nmap.org/nsedoc/scripts/http-phpself-xss.html;\
  ;http-phpself-xss;--script http-phpself-xss" \
  #
  "https://nmap.org/nsedoc/scripts/http-proxy-brute.html;\
  ;http-proxy-brute;--script http-proxy-brute" \
  #
  "https://nmap.org/nsedoc/scripts/http-put.html;\
  ;http-put;--script http-put" \
  #
  "https://nmap.org/nsedoc/scripts/http-referer-checker.html;\
  ;http-referer-checker;--script http-referer-checker" \
  #
  "https://nmap.org/nsedoc/scripts/http-security-headers.html;\
  ;http-security-headers;--script http-security-headers" \
  #
  "https://nmap.org/nsedoc/scripts/http-server-header.html;\
  ;http-server-header;--script http-server-header" \
  #
  "https://nmap.org/nsedoc/scripts/http-sitemap-generator.html;\
  ;http-sitemap-generator;--script http-sitemap-generator" \
  #
  "https://nmap.org/nsedoc/scripts/http-shellshock.html;\
  ;http-shellshock;--script http-shellshock" \
  #
  "https://nmap.org/nsedoc/scripts/http-slowloris.html;\
  ;http-slowloris;--script http-slowloris" \
  #
  "https://nmap.org/nsedoc/scripts/http-slowloris-check.html;\
  ;http-slowloris-check;--script http-slowloris-check" \
  #
  "https://nmap.org/nsedoc/scripts/http-sql-injection.html;\
  ;http-sql-injection;--script http-sql-injection" \
  #
  "https://nmap.org/nsedoc/scripts/http-stored-xss.html;\
  ;http-stored-xss;--script http-stored-xss" \
  #
  "https://nmap.org/nsedoc/scripts/http-trace.html;\
  ;http-trace;--script http-trace" \
  #
  "https://nmap.org/nsedoc/scripts/http-traceroute.html;\
  ;http-traceroute;--script http-traceroute" \
  #
  "https://nmap.org/nsedoc/scripts/http-unsafe-output-escaping.html;\
  ;http-unsafe-output-escaping;--script http-unsafe-output-escaping" \
  #
  "https://nmap.org/nsedoc/scripts/http-useragent-tester.html;\
  ;http-useragent-tester;--script http-useragent-tester" \
  #
  "https://nmap.org/nsedoc/scripts/http-userdir-enum.html;\
  ;http-userdir-enum;--script http-userdir-enum" \
  #
  "https://nmap.org/nsedoc/scripts/http-vhosts.html;\
  ;http-vhosts;--script http-vhosts" \
  #
  "https://nmap.org/nsedoc/scripts/http-xssed.html;\
  ;http-xssed;--script http-xssed" \
  #
  "https://nmap.org/nsedoc/scripts/url-snarf.html;\
  ;url-snarf;--script url-snarf" \
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
