#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: os_detection()
#
# Description:
#   OS Detection module.
#
# Usage:
#   os_detection
#
# Examples:
#   os_detection
#

function os_detection() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="os_detection"
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
  contact="contact@nslab.at"
  version="1.0"
  description="Nmap OS Detection module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      One of Nmap's best-known features is remote OS detection using TCP/IP
      stack fingerprinting. Nmap sends a series of TCP and UDP packets to the
      remote host and examines practically every bit in the responses.

      OS detection enables some other tests which make use of information that
      is gathered during the process anyway.

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

  # ---------------------------------------------------------------------------------------\n

  # shellcheck disable=SC2034
  _module_commands=(\
  #
  "Enables OS detection (TCP/IP fingerprint), as discussed above.\n \
  Alternatively, you can use -A to enable OS detection along with other\n \
  things.\n \
  \n https://nmap.org/book/man-os-detection.html;\
  ;os_detection;-O" \
  #
  "OS detection (open/closed TCP port are not found). OS detection is far more\n \
  effective if at least one open and one closed TCP port are found. Set this\n \
  option and Nmap will not even try OS detection against hosts that do not meet\n \
  this criteria. This can save substantial time, particularly on -Pn scans\n \
  against many hosts. It only matters when OS detection is requested with -O or\n \
  -A.\n \
  \n https://nmap.org/book/man-os-detection.html;\
  ;os_limit;-O --osscan-limit" \
  #
  "When Nmap is unable to detect a perfect OS match, it sometimes offers up\n \
  near-matches as possibilities. The match has to be very close for Nmap to do\n \
  this by default. Either of these (equivalent) options make Nmap guess more\n \
  aggressively. Nmap will still tell you when an imperfect match is printed\n \
  and display its confidence level (percentage) for each guess.\n \
  \n https://nmap.org/book/man-os-detection.html;\
  ;guess_aggressive;-O --osscan-guess" \
  #
  "When Nmap performs OS detection against a target and fails to find a perfect\n \
  match, it usually repeats the attempt. By default, Nmap tries five times if\n \
  conditions are favorable for OS fingerprint submission, and twice when\n \
  conditions aren't so good. Specifying a lower --max-os-tries value (such as 1)\n \
  speeds Nmap up, though you miss out on retries which could potentially\n \
  identify the OS. Alternatively, a high value may be set to allow even more\n \
  retries when conditions are favorable. This is rarely done, except to generate\n \
  better fingerprints for submission and integration into the Nmap OS\n \
  database.\n \
  \n https://nmap.org/book/man-os-detection.html;\
  ;max_detect;-O --max-os-tries 1" \
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
