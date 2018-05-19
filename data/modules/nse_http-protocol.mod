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
  description="NSE HTTP Protocol Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s: \\e[1;32m%s\\e[m" "
  Module" "${module_name}")

  _module_help+=$(printf "%s" "

    Description
    -----------

      NSE HTTP Protocol Module.

    Commands
    --------

      help    <module>                display module or NSE help
      show    <key>                   display module or profile info
      config  <key>                   show module configuration
      set     <key>                   set module variable value
      use     <module>                reuse module (changed env)
      pushd   <key>|init|show|flush   command line commands stack
      search  <key>                   search key in all commands
      init    <alias|id> [--args]     run profile

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
  "https://nmap.org/nsedoc/scripts/http-affiliate-id.html;\
  ;http-affiliate-id;--script=http-affiliate-id;\
  \"http-affiliate-id.url-path=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-auth.html;\
  ;http-auth;--script=http-auth;\
  \"http-auth.path\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-auth-finder.html;\
  ;http-auth-finder;--script=http-auth-finder;\
  \"http-auth-finder.url=/\",\"http-auth-finder.maxdepth=3\",\
  \"http-auth-finder.maxpagecount=20\",\"http-auth-finder.withinhost=true\",\
  \"http-auth-finder.withindomain=false\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-backup-finder.html;\
  ;http-backup-finder;--script=http-backup-finder;\
  \"http-backup-finder.maxpagecount=20\",\"http-backup-finder.withindomain=false\",\
  \"http-backup-finder.maxdepth=3\",\"http-backup-finder.url=/\",\
  \"http-backup-finder.withinhost=true\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-brute.html;\
  ;http-brute;--script=http-brute;\
  \"http-brute.hostname\",\"http-brute.method=GET\",\
  \"http-brute.path=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-chrono.html;\
  ;http-chrono;--script=http-chrono;\
  \"http-chrono.tries\",\"http-chrono.withindomain=false\",\
  \"http-chrono.withinhost=true\",\"http-chrono.maxdepth=3\",\
  \"http-chrono.maxpagecount=1\",\"http-chrono.url=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-comments-displayer.html;\
  ;http-comments-displayer;--script=http-comments-displayer;\
  \"http-comments-displayer.singlepages\",\"http-comments-displayer.context=0\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-config-backup.html;\
  ;http-config-backup;--script=http-config-backup;\
  \"http-config-backup.save\",\"http-config-backup.path\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-cookie-flags.html;\
  ;http-cookie-flags;--script=http-cookie-flags;\
  \"cookie\",\"path=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-cors.html;\
  ;http-cors;--script=http-cors;\
  \"http-cors.path=/\",\"http-cors.origin=example.com\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-cross-domain-policy.html;\
  ;http-cross-domain-policy;--script=http-cross-domain-policy;\
  \"http-cross-domain-policy.domain-lookup=false\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-csrf.html;\
  ;http-csrf;--script=http-csrf;\
  \"http-csrf.singlepages\",\"http-csrf.checkentropy=true\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-date.html;\
  ;http-date;--script=http-date" \
  #
  "https://nmap.org/nsedoc/scripts/http-default-accounts.html;\
  ;http-default-accounts;--script=http-default-accounts;\
  \"http-default-accounts.category\",\"http-default-accounts.fingerprintfile=http-default-accounts-fingerprints.lua\",\
  \"http-default-accounts.basepath=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-devframework.html;\
  ;http-devframework;--script=http-devframework;\
  \"http-devframework.fingerprintfile=nselib/data/http-devframework-fingerprints.lua\",\
  \"http-devframework.rapid=false\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-dombased-xss.html;\
  ;http-dombased-xss;--script=http-dombased-xss;\
  \"http-dombased-xss.singlepages\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-errors.html;\
  ;http-errors;--script=http-errors;\
  \"http-errors.errcodes\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-fileupload-exploiter.html;\
  ;http-fileupload-exploiter;--script=http-fileupload-exploiter;\
  \"http-fileupload-exploiter.fieldvalues={}\",\"http-fileupload-exploiter.formpaths\",\
  \"http-fileupload-exploiter.uploadspaths={'/uploads', '/upload', '/file', '/files', '/downloads'}\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-form-brute.html;\
  ;http-form-brute;--script=http-form-brute;\
  \"http-form-brute.hostname\",\"http-form-brute.path\",\
  \"http-form-brute.onfailure\",\"http-form-brute.sessioncookies=true\",\
  \"http-form-brute.passvar\",\"http-form-brute.onsuccess\",\
  \"http-form-brute.uservar\",\"http-form-brute.method=POST\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-form-fuzzer.html;\
  ;http-form-fuzzer;--script=http-form-fuzzer;\
  \"http-form-fuzzer.minlength=300000\",\"http-form-fuzzer.maxlength=310000\",
  \"http-form-fuzzer.targets=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-frontpage-login.html;\
  ;http-frontpage-login;--script=http-frontpage-login;\
  \"http-frontpage-login.path=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-grep.html;\
  ;http-grep;--script=http-grep;\
  \"http-grep.breakonmatch\",\"http-grep.builtins\",\
  \"http-grep.maxdepth=3\",\"http-grep.withinhost=true\",\
  \"http-grep.withindomain=false\",\"http-grep.match\",\
  \"http-grep.maxpagecount=20\",\"http-grep.url=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-headers.html;\
  ;http-headers;--script=http-headers;\
  \"useget\",\"path=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-internal-ip-disclosure.html;\
  ;http-internal-ip-disclosure;--script=http-internal-ip-disclosure;\
  \"http-internal-ip-disclosure.path=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-ls.html;\
  ;http-ls;--script=http-ls;\
  \"http-ls.url=/\",\"http-ls.checksum=false\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-mcmp.html;\
  ;http-mcmp;--script=http-mcmp" \
  #
  "https://nmap.org/nsedoc/scripts/http-method-tamper.html;\
  ;http-method-tamper;--script=http-method-tamper;\
  \"http-method-tamper.timeout=10s\",\"http-method-tamper.uri\",\
  \"http-method-tamper.paths\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-methods.html;\
  ;http-methods;--script=http-methods;\
  \"http-methods.url-path=/\",\"http-methods.test-all\",\
  \"http-methods.retest\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-open-proxy.html;\
  ;http-open-proxy;--script=http-open-proxy" \
  #
  "https://nmap.org/nsedoc/scripts/http-open-redirect.html;\
  ;http-open-redirect;--script=http-open-redirect;\
  \"http-open-redirect.maxdepth=3\",\"http-open-redirect.maxpagecount=20\",\
  \"http-open-redirect.url=/\",\"http-open-redirect.withindomain=false\",\
  \"http-open-redirect.withinhost=true\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-phpself-xss.html;\
  ;http-phpself-xss;--script=http-phpself-xss;\
  \"http-phpself-xss.timeout=10s\",\"http-phpself-xss.uri=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-proxy-brute.html;\
  ;http-proxy-brute;--script=http-proxy-brute;\
  \"http-proxy-brute.url=http://scanme.insecure.org\",\"http-proxy-brute.method=HEAD\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-put.html;\
  ;http-put;--script=http-put;\
  \"http-put.file\",\"http-put.url\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-referer-checker.html;\
  ;http-referer-checker;--script=http-referer-checker" \
  #
  "https://nmap.org/nsedoc/scripts/http-security-headers.html;\
  ;http-security-headers;--script=http-security-headers;\
  \"http-security-headers.path\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-server-header.html;\
  ;http-server-header;--script=http-server-header" \
  #
  "https://nmap.org/nsedoc/scripts/http-sitemap-generator.html;\
  ;http-sitemap-generator;--script=http-sitemap-generator;\
  \"http-sitemap-generator.withindomain=false\",\"http-sitemap-generator.maxdepth=3\",\
  \"http-sitemap-generator.maxpagecount=20\",\"http-sitemap-generator.url=/\",\
  \"http-sitemap-generator.withinhost=true\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-shellshock.html;\
  ;http-shellshock;--script=http-shellshock;\
  \"http-shellshock.uri=/\",\"http-shellshock.header=User-Agent\",\
  \"http-shellshock.cmd\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-slowloris.html;\
  ;http-slowloris;--script=http-slowloris;\
  \"http-slowloris.runforever=false\",\"http-slowloris.timelimit=30m\",\
  \"http-slowloris.send_interval=100s\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-slowloris-check.html;\
  ;http-slowloris-check;--script=http-slowloris-check" \
  #
  "https://nmap.org/nsedoc/scripts/http-sql-injection.html;\
  ;http-sql-injection;--script=http-sql-injection;\
  \"http-sql-injection.withinhost=true\",\"http-sql-injection.errorstrings=nselib/data/http-sql-errors.lst\",\
  \"http-sql-injection.withindomain=false\",\"http-sql-injection.url=/\",\
  \"http-sql-injection.maxpagecount=20\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-stored-xss.html;\
  ;http-stored-xss;--script=http-stored-xss;\
  \"http-stored-xss.formpaths\",\"http-stored-xss.uploadspaths\",\
  \"http-stored-xss.fieldvalues={}\",\"http-stored-xss.dbfile\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-trace.html;\
  ;http-trace;--script=http-trace;\
  \"http-trace.path\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-traceroute.html;\
  ;http-traceroute;--script=http-traceroute;\
  \"http-traceroute.path=/\",\"http-traceroute.method=GET\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-unsafe-output-escaping.html;\
  ;http-unsafe-output-escaping;--script=http-unsafe-output-escaping;\
  \"http-unsafe-output-escaping.withinhost=true\",\"http-unsafe-output-escaping.url=/\",\
  \"http-unsafe-output-escaping.maxdepth=3\",\"http-unsafe-output-escaping.withindomain=false\",\
  \"http-unsafe-output-escaping.maxpagecount=20\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-useragent-tester.html;\
  ;http-useragent-tester;--script=http-useragent-tester;\
  \"http-useragent-tester.useragents\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-userdir-enum.html;\
  ;http-userdir-enum;--script=http-userdir-enum;\
  \"http-userdir-enum.limit\",\"http-userdir-enum.users\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vhosts.html;\
  ;http-vhosts;--script=http-vhosts;\
  \"http-vhosts.filelist=nselib/data/vhosts-default.lst\",\"http-vhosts.collapse=20\",\
  \"http-vhosts.path=/\",\"http-vhosts.domain\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-xssed.html;\
  ;http-xssed;--script=http-xssed" \
  #
  "https://nmap.org/nsedoc/scripts/url-snarf.html;\
  ;url-snarf;--script=url-snarf;\
  \"url-snarf.outfile\",\"url-snarf.timeout=30s\",\
  \"url-snarf.interface\",\"url-snarf.nostdout\"" \
  )

  # shellcheck disable=SC2034,SC2154
  _module_show=(\
      "${module_name}" \
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
