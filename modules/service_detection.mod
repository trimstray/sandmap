#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: service_detection()
#
# Description:
#   Service and Version Detection module.
#
# Usage:
#   service_detection
#
# Examples:
#   service_detection
#

function service_detection() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="service_detection"
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
  description="Service and Version Detection module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Point Nmap at a remote machine and it might tell you that ports 25/tcp,
      80/tcp, and 53/udp are open. Using its nmap-services database of about
      2,200 well-known services, Nmap would report that those ports probably
      correspond to a mail server (SMTP), web server (HTTP), and name server
      (DNS) respectively. This lookup is usually accurate-the vast majority of
      daemons listening on TCP port 25 are, in fact, mail servers. However, you
      should not bet your security on this! People can and do run services on
      strange ports.

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

  # ---------------------------------------------------------------------------------------\n

  # shellcheck disable=SC2034
  _module_commands=(\
  #
  "https://nmap.org/book/man-version-detection.html;\
  ;version_detection;-sV" \
  #
  "https://nmap.org/book/man-version-detection.html;\
  ;more_aggressive;-sV --version-intensity 5" \
  #
  "https://nmap.org/book/man-version-detection.html;\
  ;light;-sV --version-ligh" \
  #
  "https://nmap.org/book/man-version-detection.html;\
  ;banner;-sV --version-intensity 0" \
  #
  "https://nmap.org/book/man-version-detection.html;\
  ;version_all;-sV --version-all" \
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
