#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_http-cve()
#
# Description:
#   NSE HTTP Vulnerability CVE Module.
#
# Usage:
#   nse_http-cve
#
# Examples:
#   nse_http-cve
#

function nse_http-cve() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_http-cve"
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
  description="NSE HTTP Vulnerability CVE Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s: \\e[1;32m%s\\e[m" "
  Module" "${module_name}")

  _module_help+=$(printf "%s" "

    Description
    -----------

      NSE HTTP Vulnerability CVE Module.

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
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2006-3392.html;\
  ;http-vuln-cve2006-3392;--script=http-vuln-cve2006-3392;\
  \"http-vuln-cve2006-3392.file=/etc/passwd\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2009-3960.html;\
  ;http-vuln-cve2009-3960;--script=http-vuln-cve2009-3960;\
  \"http-vuln-cve2009-3960.root/\",\"http-vuln-cve2009-3960.readfile=/etc/passwd\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2010-0738.html;\
  ;http-vuln-cve2010-0738;--script=http-vuln-cve2010-0738;\
  \"http-vuln-cve2010-0738.paths={\"/jmx-console/\"}\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2010-2861.html;\
  ;http-vuln-cve2010-2861;--script=http-vuln-cve2010-2861" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2011-3192.html;\
  ;http-vuln-cve2011-3192;--script=http-vuln-cve2011-3192;\
  \"http-vuln-cve2011-3192.path\",\"http-vuln-cve2011-3192.hostname\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2011-3368.html;\
  ;http-vuln-cve2011-3368;--script=http-vuln-cve2011-3368;\
  \"http-vuln-cve2011-3368.prefix\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2012-1823.html;\
  ;http-vuln-cve2012-1823;--script=http-vuln-cve2012-1823;\
  \"http-vuln-cve2012-1823.uri=/index.php\",\"http-vuln-cve2012-1823.cmd=uname -a\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2013-0156.html;\
  ;http-vuln-cve2013-0156;--script=http-vuln-cve2013-0156;\
  \"http-vuln-cve2013-0156.uri=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2013-6786.html;\
  ;http-vuln-cve2013-6786;--script=http-vuln-cve2013-6786" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2013-7091.html;\
  ;http-vuln-cve2013-7091;--script=http-vuln-cve2013-7091;\
  \"http-vuln-cve2013-7091.uri=/zimbra\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2014-2126.html;\
  ;http-vuln-cve2014-2126;--script=http-vuln-cve2014-2126" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2014-2127.html;\
  ;http-vuln-cve2014-2127;--script=http-vuln-cve2014-2127" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2014-2128.html;\
  ;http-vuln-cve2014-2128;--script=http-vuln-cve2014-2128" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2014-2129.html;\
  ;http-vuln-cve2014-2129;--script=http-vuln-cve2014-2129" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2014-3704.html;\
  ;http-vuln-cve2014-3704;--script=http-vuln-cve2014-3704;\
  \"http-vuln-cve2014-3704.uri=/\",\"http-vuln-cve2014-3704.cmd\",\
  \"http-vuln-cve2014-3704.cleanup=true\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2014-8877.html;\
  ;http-vuln-cve2014-8877;--script=http-vuln-cve2014-8877;\
  \"http-vuln-cve2014-8877.cmd\",\"http-vuln-cve2014-8877.uri=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2015-1427.html;\
  ;http-vuln-cve2015-1427;--script=http-vuln-cve2015-1427;\
  \"command\",\"invasive\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2015-1635.html;\
  ;http-vuln-cve2015-1635;--script=http-vuln-cve2015-1635;\
  \"http-vuln-cve2015-1635.uri=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2017-1001000.html;\
  ;http-vuln-cve2017-1001000;--script=http-vuln-cve2017-1001000;\
  \"http-vuln-cve2017-1001000.uri=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2017-5638.html;\
  ;http-vuln-cve2017-5638;--script=http-vuln-cve2017-5638;\
  \"http-vuln-cve2017-5638.path=/\",\"http-vuln-cve2017-5638.method=GET\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2017-5689.html;\
  ;http-vuln-cve2017-5689;--script=http-vuln-cve2017-5689" \
  #
  "https://nmap.org/nsedoc/scripts/http-vuln-cve2017-8917.html;\
  ;http-vuln-cve2017-8917;--script=http-vuln-cve2017-8917;\
  \"http-vuln-cve2017-8917.uri\"" \
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
