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
  "No Scan, List targets only. When a List Scan is performed, Nmap will attempt\n \
  to perform a reverse DNS lookup to identify the FQDN of the host(s) to be\n \
  scanned. Resolved names will be included as part of the scan results.\n \
  \n https://nmap.org/book/man-host-discovery.html;\
  ;list_scan;-sL $_cmd_params" \
  #
  "No port scanning, Host discovery only. This option tells Nmap not to do a\n \
  port scan after host discovery, and only print out the available hosts that\n \
  responded to the host discovery probes. This is often known as a \"ping\n \
  scan\", but you can also request that traceroute and NSE host scripts be run.\n \
  \n https://nmap.org/book/man-host-discovery.html;\
  ;no_port_scan;-sn $_cmd_params" \
  #
  "No host discovery, Port scan only. This option skips the Nmap discovery stage\n \
  altogether. Normally, Nmap uses this stage to determine active machines for\n \
  heavier scanning. By default, Nmap only performs heavy probing such as port\n \
  scans, version detection or OS detection against hosts that are found to be\n \
  up. Disabling host discovery with -Pn causes Nmap to attempt the requested\n \
  scanning functions against every target IP address specified.\n \
  \n https://nmap.org/book/man-host-discovery.html;\
  ;no_ping;-Pn $_cmd_params" \
  #
  "TCP SYN discovery. This option sends an empty TCP packet with the SYN flag\n \
  set. The SYN flag suggests to the remote system that you are attempting to\n \
  establish a connection. Normally the destination port will be closed, and a\n \
  RST (reset) packet sent back. If the port happens to be open, the target will\n \
  take the second step of a TCP three-way-handshake by responding with\n \
  a SYN/ACK TCP packet.\n \
  \n https://nmap.org/book/man-host-discovery.html;\
  ;tcp_syn_ping;-PS -p $_cmd_params" \
  #
  "TCP ACK discovery. The TCP ACK ping is quite similar to the just-discussed\n \
  SYN ping. The difference, as you could likely guess, is that the TCP ACK flag\n \
  is set instead of the SYN flag. Such an ACK packet purports to be\n \
  acknowledging data over an established TCP connection, but no such connection\n \
  exists. So remote hosts should always respond with a RST packet, disclosing\n \
  their existence in the process.\n \
  \n https://nmap.org/book/man-host-discovery.html;\
  ;tcp_ack_ping;-PA -p 80 $_cmd_params" \
  #
  "UDP discovery. Another host discovery option is the UDP ping, which sends a\n \
  UDP packet to the given ports. For most ports, the packet will be empty,\n \
  though some use a protocol-specific payload that is more likely to elicit a\n \
  response.\n \
  \n https://nmap.org/book/man-host-discovery.html;\
  ;udp_ping;-PU -p 80 $_cmd_params" \
  #
  "This option sends an SCTP packet containing a minimal INIT chunk. The INIT\n \
  chunk suggests to the remote system that you are attempting to establish an\n \
  association. Normally the destination port will be closed, and an ABORT chunk\n \
  will be sent back. If the port happens to be open, the target will take the\n \
  second step of an SCTP four-way-handshake by responding with an INIT-ACK\n \
  chunk.\n \
  \n https://nmap.org/book/man-host-discovery.html;\
  ;sctp_init_ping;-PY -p 80 $_cmd_params" \
  #
  "ARP discovery on local network. One of the most common Nmap usage scenarios\n \
  is to scan an ethernet LAN. On most LANs, especially those using private\n \
  address ranges specified by RFC 1918, the vast majority of IP addresses are\n \
  unused at any given time. When Nmap tries to send a raw IP packet such as an\n \
  ICMP echo request, the operating system must determine the destination\n \
  hardware (ARP) address corresponding to the target IP so that it can properly\n \
  address the ethernet frame.\n \
  \n https://nmap.org/book/man-host-discovery.html;\
  ;arp_ping;-PR $_cmd_params" \
  #
  "Nmap sends an ICMP type 8 (echo request) packet to the target IP addresses,\n \
  expecting a type 0 (echo reply) in return from available hosts. Unfortunately\n \
  for network explorers, many hosts and firewalls now block these packets,\n \
  rather than responding as required by RFC 1122. For this reason, ICMP-only\n \
  scans are rarely reliable enough against unknown targets over the Internet.\n \
  But for system administrators monitoring an internal network, they can be a\n \
  practical and efficient approach. Use the -PE option to enable this echo\n \
  request behavior.\n \
  \n https://nmap.org/book/man-host-discovery.html;\
  ;icmp_ping-1;-PE $_cmd_params" \
  #
  "While echo request is the standard ICMP ping query, Nmap does not stop\n \
  there. The ICMP standards (RFC 792 and RFC 950 ) also specify timestamp\n \
  request, information request, and address mask request packets as codes 13,\n \
  15, and 17, respectively. While the ostensible purpose for these queries is\n \
  to learn information such as address masks and current times, they can easily\n \
  be used for host discovery. A system that replies is up and available. Nmap\n \
  does not currently implement information request packets, as they are not\n \
  widely supported. RFC 1122 insists that \"a host SHOULD NOT implement these\n \
  messages\". Timestamp and address mask queries can be sent with the -PP and\n \
  -PM options, respectively. A timestamp reply (ICMP code 14) or address mask\n \
  reply (code 18) discloses that the host is available. These two queries can\n \
  be valuable when administrators specifically block echo request packets while\n \
  forgetting that other ICMP queries can be used for the same purpose.\n \
  \n https://nmap.org/book/man-host-discovery.html;\
  ;icmp_ping-2;-PP $_cmd_params" \
  #
  "While echo request is the standard ICMP ping query, Nmap does not stop\n \
  there. The ICMP standards (RFC 792 and RFC 950 ) also specify timestamp\n \
  request, information request, and address mask request packets as codes 13,\n \
  15, and 17, respectively. While the ostensible purpose for these queries is\n \
  to learn information such as address masks and current times, they can easily\n \
  be used for host discovery. A system that replies is up and available. Nmap\n \
  does not currently implement information request packets, as they are not\n \
  widely supported. RFC 1122 insists that \"a host SHOULD NOT implement these\n \
  messages\". Timestamp and address mask queries can be sent with the -PP and\n \
  -PM options, respectively. A timestamp reply (ICMP code 14) or address mask\n \
  reply (code 18) discloses that the host is available. These two queries can\n \
  be valuable when administrators specifically block echo request packets while\n \
  forgetting that other ICMP queries can be used for the same purpose.\n \
  \n https://nmap.org/book/man-host-discovery.html;\
  ;icmp_ping-3;-PM $_cmd_params" \
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
