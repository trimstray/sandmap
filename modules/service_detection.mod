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
  contact="contact@nslab.at"
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
      init    <value>                 run predefined scanning command

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
  "Enables version detection, as discussed above. Alternatively, you can use -A,\n \
  which enables version detection among other things.\n \
  \n https://nmap.org/book/man-version-detection.html;\
  ;version_detection;-sV" \
  #
  "When performing a version scan (-sV), Nmap sends a series of probes, each of\n \
  which is assigned a rarity value between one and nine. The lower-numbered\n \
  probes are effective against a wide variety of common services, while the\n \
  higher-numbered ones are rarely useful. The intensity level specifies which\n \
  probes should be applied. The higher the number, the more likely it is the\n \
  service will be correctly identified. However, high intensity scans take\n \
  longer. The intensity must be between 0 and 9. The default is 7. When a probe\n \
  is registered to the target port via the nmap-service-probes ports directive,\n \
  that probe is tried regardless of intensity level. This ensures that the DNS\n \
  probes will always be attempted against any open port 53, the SSL probe will\n \
  be done against 443, etc.\n \
  \n https://nmap.org/book/man-version-detection.html;\
  ;more_aggressive;-sV --version-intensity 5" \
  #
  "This is a convenience alias for --version-intensity 2. This light mode makes\n \
  version scanning much faster, but it is slightly less likely to identify\n \
  services.\n \
  \n https://nmap.org/book/man-version-detection.html;\
  ;light;-sV --version-ligh" \
  #
  "This banner mode makes version scanning much faster, but it is slightly less
  likely to identify service banner.\n \
  \n https://nmap.org/book/man-version-detection.html;\
  ;banner;-sV --version-intensity 0" \
  #
  "An alias for --version-intensity 9, ensuring that every single probe is\n \
  attempted against each port.\n \
  \n https://nmap.org/book/man-version-detection.html;\
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
