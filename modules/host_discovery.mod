#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: host_discovery()
#
# Description:
#   Nmap Host Discovery module.
#
# Usage:
#   host_discovery
#
# Examples:
#   host_discovery
#

function host_discovery() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="host_discovery"
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
  description="Nmap Host Discovery module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Nmap does host discovery and then performs a port
      scan against each host it determines is online.

    Commands
    --------

      help                          display module help
      show    <key>                 display module or profile info
      config  <key>                 show module configuration
      set     <key>                 set module variable value
      init    <value>               run predefined scanning command

      Options:

        <key>                       key value
        <value>                     profile alias or id

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
  "No Scan, List targets only. When a List Scan is performed, Nmap will attempt\n to perform a reverse DNS lookup to identify the FQDN of the host(s) to be scanned.\n Resolved names will be included as part of the scan results.\n \n https://nmap.org/book/man-host-discovery.html;\
  ;list_scan;-sL" \
  #
  "No port scanning, Host discovery only. This option tells Nmap not to do a port\n scan after host discovery, and only print out the available hosts that responded\n to the host discovery probes. This is often known as a \"ping scan\",\n but you can also request that traceroute and NSE host scripts be run.\n \n https://nmap.org/book/man-host-discovery.html;\
  ;no_port_scan;-sn" \
  #
  "No host discovery, Port scan only. This option skips the Nmap discovery stage altogether.\n Normally, Nmap uses this stage to determine active machines for heavier scanning.\n By default, Nmap only performs heavy probing such as port scans, version detection\n or OS detection against hosts that are found to be up. Disabling host discovery with -Pn\n causes Nmap to attempt the requested scanning functions against every target IP address specified.\n \n https://nmap.org/book/man-host-discovery.html;\
  ;no_ping;-Pn" \
  #
  "TCP SYN discovery. This option sends an empty TCP packet with the SYN flag set. The default\n destination port is 80 (configurable at compile time by changing DEFAULT_TCP_PROBE_PORT_SPEC\n in nmap.h). Alternate ports can be specified as a parameter.\n \n https://nmap.org/book/man-host-discovery.html;\
  ;tcp_syn_ping;-PS -p $port" \
  #
  "TCP ACK discovery. The TCP ACK ping is quite similar to the just-discussed SYN ping.\n The difference, as you could likely guess, is that the TCP ACK flag is set instead of\n the SYN flag. Such an ACK packet purports to be acknowledging data over an established\n TCP connection, but no such connection exists. So remote hosts should\n always respond with a RST packet, disclosing their existence in the process.\n \n https://nmap.org/book/man-host-discovery.html;\
  ;tcp_ack_ping;-PA -p $port" \
  #
  "UDP discovery. Another host discovery option is the UDP ping, which sends a UDP packet\n to the given ports. For most ports, the packet will be empty, though some use\n a protocol-specific payload that is more likely to elicit a response.\n \n https://nmap.org/book/man-host-discovery.html;\
  ;udp_ping;-PU -p $port" \
  #
  "ARP discovery on local network;\
  ;arp_disc;-PR" \
  #
  "Never do DNS resolution;\
  ;no_dns;-n" \
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
