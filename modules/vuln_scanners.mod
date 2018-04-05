#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: vuln_scanners()
#
# Description:
#   Vulnerability Scanners Module.
#
# Usage:
#   vuln_scanners
#
# Examples:
#   vuln_scanners
#

function vuln_scanners() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="vuln_scanners"
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
  description="Vulnerability Scanners Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Vulnerability Scanners Module.

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
  "User Summary:\n \n \
  Performs brute force password auditing against a Nessus vulnerability scanning\n \
  daemon using the NTP 1.2 protocol.\n \n \
  Script Arguments:\n \n \
  - passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb\n \
  See the documentation for the unpwdb library.\n \n \
  - creds.[service], creds.global\n \
  See the documentation for the creds library.\n \n \
  - brute.credfile, brute.delay, brute.emptypass, brute.firstonly,\n \
  brute.guesses, brute.mode, brute.passonly, brute.retries, brute.start,\n \
  brute.threads, brute.unique, brute.useraspass\n \
  See the documentation for the brute library.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 1241).\n \
  \n https://nmap.org/nsedoc/scripts/nessus-brute.html;\
  ;nessus-brute;--script nessus-brute $params" \
  #
  "User Summary:\n \n \
  Performs brute force password auditing against a Nessus vulnerability scanning\n \
  daemon using the XMLRPC protocol.\n \n \
  Script Arguments:\n \n \
  - nessus-xmlrpc-brute.timeout\n \
  Socket timeout for connecting to Nessus (default 5s).\n \n \
  - nessus-xmlrpc-brute.threads\n \
  Sets the number of threads.\n \n \
  - passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb\n \
  See the documentation for the unpwdb library.\n \n \
  - creds.[service], creds.global\n \
  See the documentation for the creds library.\n \n \
  - brute.credfile, brute.delay, brute.emptypass, brute.firstonly,\n \
  brute.guesses, brute.mode, brute.passonly, brute.retries, brute.start,\n \
  brute.threads, brute.unique, brute.useraspass\n \
  See the documentation for the brute library.\n \n \
  - sV\n \
  Probe open ports to determine service/version info.\n \
  \n https://nmap.org/nsedoc/scripts/nessus-xmlrpc-brute.html;\
  ;nessus-xmlrpc-brute;--script=nessus-xmlrpc-brute $params" \
  #
  "User Summary:\n \n \
  Performs brute force password auditing against a Nexpose vulnerability scanner\n \
  using the API 1.1.\n \n \
  Script Arguments:\n \n \
  - passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb\n \
  See the documentation for the unpwdb library.\n \n \
  - creds.[service], creds.global\n \
  See the documentation for the creds library.\n \n \
  - brute.credfile, brute.delay, brute.emptypass, brute.firstonly,\n \
  brute.guesses, brute.mode, brute.passonly, brute.retries, brute.start,\n \
  brute.threads, brute.unique, brute.useraspass\n \
  See the documentation for the brute library.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 3780).\n \
  \n https://nmap.org/nsedoc/scripts/nexpose-brute.html;\
  ;nexpose-brute;--script nexpose-brute $params" \
  #
  "User Summary:\n \n \
  Performs brute force password auditing against the OpenVAS manager using\n \
  OMPv2.\n \n \
  Script Arguments:\n \n \
  - omp2.password, omp2.username\n \
  See the documentation for the omp2 library.\n \n \
  - passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb\n \
  See the documentation for the unpwdb library.\n \n \
  - creds.[service], creds.global\n \
  See the documentation for the creds library.\n \n \
  - brute.credfile, brute.delay, brute.emptypass, brute.firstonly,\n \
  brute.guesses, brute.mode, brute.passonly, brute.retries, brute.start,\n \
  brute.threads, brute.unique, brute.useraspass\n \
  See the documentation for the brute library.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 9390).\n \
  \n https://nmap.org/nsedoc/scripts/omp2-brute.html;\
  ;omp2-brute;--script omp2-brute $params" \
  #
  "User Summary:\n \n \
  Attempts to retrieve the list of target systems and networks from an OpenVAS\n \
  Manager server. The script authenticates on the manager using provided or\n \
  previously cracked credentials and gets the list of defined targets for each\n \
  account.\n \n \
  Script Arguments:\n \n \
  - omp2.password, omp2.username\n \
  See the documentation for the omp2 library.\n \n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 9390).\n \
  \n https://nmap.org/nsedoc/scripts/omp2-enum-targets.html;\
  ;omp2-enum-targets;--script omp2-enum-targets $params" \
  #
  "User Summary:\n \n \
  Performs brute force password auditing against a OpenVAS vulnerability scanner\n \
  daemon using the OTP 1.0 protocol.\n \n \
  Script Arguments:\n \n \
  - openvas-otp-brute.threads\n \
  Sets the number of threads. Default: 4.\n \n \
  - passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb\n \
  See the documentation for the unpwdb library.\n \n \
  - creds.[service], creds.global\n \
  See the documentation for the creds library.\n \n \
  - brute.credfile, brute.delay, brute.emptypass, brute.firstonly,\n \
  brute.guesses, brute.mode, brute.passonly, brute.retries, brute.start,\n \
  brute.threads, brute.unique, brute.useraspass\n \
  See the documentation for the brute library.\n \n \
  - -sV\n \
  Probe open ports to determine service/version info.\n \
  \n https://nmap.org/nsedoc/scripts/openvas-otp-brute.html;\
  ;openvas-otp-brute;--script=openvas-otp-brute $params" \
  #
  "User Summary:\n \n \
  Queries Shodan API for given targets and produces similar output to a -sV nmap\n \
  scan. The ShodanAPI key can be set with the 'apikey' script argument, or\n \
  hardcoded in the .nse file itself. You can get a free key from\n \
  https://developer.shodan.io\n \n \
  Script Arguments:\n \n \
  - shodan-api.target\n \
  Specify a single target to be scanned.\n \n \
  - shodan-api.apikey\n \
  Specify the ShodanAPI key. This can also be hardcoded in the nse file.\n \n \
  - shodan-api.outfile\n \
  Write the results to the specified CSV file.\n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \n \
  - -sn\n \
  Ping Scan - disable port scan.\n \n \
  - -Pn\n \
  Treat all hosts as online -- skip host discovery.\n \
  - -n\n \
  Never do DNS resolution.\n \
  \n https://nmap.org/nsedoc/scripts/shodan-api.html;\
  ;shodan-api;--script shodan-api $params" \
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
