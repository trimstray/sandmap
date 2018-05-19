#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_smb()
#
# Description:
#   NSE SMB Protocol Module.
#
# Usage:
#   nse_smb
#
# Examples:
#   nse_smb
#

function nse_smb() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_smb"
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
  description="NSE SMB Protocol Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s: \\e[1;32m%s\\e[m" "
  Module" "${module_name}")

  _module_help+=$(printf "%s" "

    Description
    -----------

      NSE SMB Protocol Module.

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
  "https://nmap.org/nsedoc/scripts/smb-brute.html;\
  ;smb-brute;--script=smb-brute;\
  \"smblockout\",\"canaries=3\",\"brutelimit=5000\"" \
  #
  "https://nmap.org/nsedoc/scripts/smb-double-pulsar-backdoor.html;\
  ;smb-double-pulsar-backdoor;--script=smb-double-pulsar-backdoor" \
  #
  "https://nmap.org/nsedoc/scripts/smb-enum-domains.html;\
  ;smb-enum-domains;--script=smb-enum-domains" \
  #
  "https://nmap.org/nsedoc/scripts/smb-enum-groups.html;\
  ;smb-enum-groups;--script=smb-enum-groups" \
  #
  "https://nmap.org/nsedoc/scripts/smb-enum-processes.html;\
  ;smb-enum-processes;--script=smb-enum-processes" \
  #
  "https://nmap.org/nsedoc/scripts/smb-enum-services.html;\
  ;smb-enum-services;--script=smb-enum-services" \
  #
  "https://nmap.org/nsedoc/scripts/smb-enum-sessions.html;\
  ;smb-enum-sessions;--script=smb-enum-sessions" \
  #
  "https://nmap.org/nsedoc/scripts/smb-enum-shares.html;\
  ;smb-enum-shares;--script=smb-enum-shares" \
  #
  "https://nmap.org/nsedoc/scripts/smb-enum-users.html;\
  ;smb-enum-users;--script=smb-enum-users;\
  \"samronly\",\"lsaonly\"" \
  #
  "https://nmap.org/nsedoc/scripts/smb-flood.html;\
  ;smb-flood;--script=smb-flood" \
  #
  "https://nmap.org/nsedoc/scripts/smb-ls.html;\
  ;smb-ls;--script=smb-ls;\
  \"smb-ls.path=/\",\"smb-ls.pattern=*\",\"smb-ls.share(s)\",\
  \"smb-ls.checksum=false\"" \
  #
  "https://nmap.org/nsedoc/scripts/smb-mbenum.html;\
  ;smb-mbenum;--script=smb-mbenum;\
  \"smb-mbenum.format=3\",\"smb-mbenum.domain\",\
  \"smb-mbenum.filter\"" \
  #
  "https://nmap.org/nsedoc/scripts/smb-os-discovery.html;\
  ;smb-os-discovery;--script=smb-os-discovery" \
  #
  "https://nmap.org/nsedoc/scripts/smb-print-text.html;\
  ;smb-print-text;--script=smb-print-text;\
  \"text\",\"filename\",\"printer\"" \
  #
  "https://nmap.org/nsedoc/scripts/smb-protocols.html;\
  ;smb-protocols;--script=smb-protocols" \
  #
  "https://nmap.org/nsedoc/scripts/smb-psexec.html;\
  ;smb-psexec;--script=smb-psexec;\
  \"nohide\",\"cleanup\",\"nocipher\",\"sharepath\",\
  \"config\",\"time=15s\",\"nocleanup\",\"key\",\"share\"" \
  #
  "https://nmap.org/nsedoc/scripts/smb-security-mode.html;\
  ;smb-security-mode;--script=smb-security-mode" \
  #
  "https://nmap.org/nsedoc/scripts/smb-server-stats.html;\
  ;smb-server-stats;--script=smb-server-stats" \
  #
  "https://nmap.org/nsedoc/scripts/smb-system-info.html;\
  ;smb-system-info;--script=smb-system-info" \
  #
  "https://nmap.org/nsedoc/scripts/smb2-capabilities.html;\
  ;smb2-capabilities;--script=smb2-capabilities" \
  #
  "https://nmap.org/nsedoc/scripts/smb2-security-mode.html;\
  ;smb2-security-mode;--script=smb2-security-mode" \
  #
  "https://nmap.org/nsedoc/scripts/smb2-time.html;\
  ;smb2-time;--script=smb2-time" \
  #
  "https://nmap.org/nsedoc/scripts/smb2-vuln-uptime.html;\
  ;smb2-vuln-uptime;--script=smb2-vuln-uptime;\
  \"smb2-vuln-uptime.skip-os\"" \
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
