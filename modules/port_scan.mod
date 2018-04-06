#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: port_scan()
#
# Description:
#   Nmap Port Scan types module.
#
# Usage:
#   port_scan
#
# Examples:
#   port_scan
#

function port_scan() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="port_scan"
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
  description="Nmap Port Scan types module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      This section documents the dozen or so port scan techniques supported by
      Nmap. Only one method may be used at a time, except that UDP scan (-sU)
      and any one of the SCTP scan types (-sY, -sZ) may be combined with any one
      of the TCP scan types. As a memory aid, port scan type options are of the
      form -s<C>, where <C> is a prominent character in the scan name, usually
      the first. The one exception to this is the deprecated FTP bounce scan
      (-b). By default, Nmap performs a SYN Scan, though it substitutes a
      connect scan if the user does not have proper privileges to send raw
      packets (requires root access on Unix).

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
  "SYN scan is the default and most popular scan option for good reasons. This\n \
  technique is often referred to as half-open scanning, because you don't\n \
  open a full TCP connection. You send a SYN packet, as if you are going to open\n \
  a real connection and then wait for a response. A SYN/ACK indicates the port\n \
  is listening (open), while a RST (reset) is indicative of a non-listener. If\n \
  no response is received after several retransmissions, the port is marked as\n \
  filtered. The port is also marked filtered if an ICMP unreachable error (type\n \
  3, code 0, 1, 2, 3, 9, 10, or 13) is received. The port is also considered\n \
  open if a SYN packet (without the ACK flag) is received in response. This can\n \
  be due to an extremely rare TCP feature known as a simultaneous open or split\n \
  handshake connection (see https://nmap.org/misc/split-handshake.pdf).\n \
  \n https://nmap.org/book/man-port-scanning-techniques.html;\
  ;tcp_syn;-sS" \
  #
  "TCP connect scan is the default TCP scan type when SYN scan is not an option.\n \
  When SYN scan is available, it is usually a better choice. Nmap has less\n \
  control over the high level connect call than with raw packets, making it less\n \
  efficient. The system call completes connections to open target ports rather\n \
  than performing the half-open reset that SYN scan does. Not only does this\n \
  take longer and require more packets to obtain the same information, but\n \
  target machines are more likely to log the connection. A decent IDS will catch\n \
  either, but most machines have no such alarm system. Many services on your\n \
  average Unix system will add a note to syslog, and sometimes a cryptic error\n \
  message, when Nmap connects and then closes the connection without sending\n \
  data. Truly pathetic services crash when this happens, though that is\n \
  uncommon. An administrator who sees a bunch of connection attempts in her logs\n \
  from a single system should know that she has been connect scanned.\n \
  \n https://nmap.org/book/man-port-scanning-techniques.html;\
  ;tcp_conn;-sT" \
  #
  "UDP scan works by sending a UDP packet to every targeted port. For some\n \
  common ports such as 53 and 161, a protocol-specific payload is sent to\n \
  increase response rate, but for most ports the packet is empty unless the\n \
  --data, --data-string, or --data-length options are specified. If an ICMP port\n \
  unreachable error (type 3, code 3) is returned, the port is closed. Other ICMP\n \
  unreachable errors (type 3, codes 0, 1, 2, 9, 10, or 13) mark the port as\n \
  filtered. Occasionally, a service will respond with a UDP packet, proving that\n \
  it is open. If no response is received after retransmissions, the port is\n \
  classified as open|filtered.\n \
  \n https://nmap.org/book/man-port-scanning-techniques.html;\
  ;udp_scan;-sU" \
  #
  "This technique is often referred to as half-open scanning, because you don't\n \
  open a full SCTP association. You send an INIT chunk, as if you are going to\n \
  open a real association and then wait for a response. An INIT-ACK chunk\n \
  indicates the port is listening (open), while an ABORT chunk is indicative of\n \
  a non-listener. If no response is received after several retransmissions, the\n \
  port is marked as filtered. The port is also marked filtered if an ICMP\n \
  unreachable error (type 3, code 0, 1, 2, 3, 9, 10, or 13) is received.\n \
  \n https://nmap.org/book/man-port-scanning-techniques.html;\
  ;sctp_scan;-sY" \
  #
  "When scanning systems compliant with this RFC text, any packet not containing\n \
  SYN, RST, or ACK bits will result in a returned RST if the port is closed and\n \
  no response at all if the port is open. As long as none of those three bits\n \
  are included, any combination of the other three (FIN, PSH, and URG) are OK.\n \
  Does not set any bits (TCP flag header is 0).\n \
  \n https://nmap.org/book/man-port-scanning-techniques.html;\
  ;null_scan;-sN" \
  #
  "When scanning systems compliant with this RFC text, any packet not containing\n \
  SYN, RST, or ACK bits will result in a returned RST if the port is closed and\n \
  no response at all if the port is open. As long as none of those three bits\n \
  are included, any combination of the other three (FIN, PSH, and URG) are OK.\n \
  Sets just the TCP FIN bit.\n \
  \n https://nmap.org/book/man-port-scanning-techniques.html;\
  ;fin_scan;-sF" \
  #
  "When scanning systems compliant with this RFC text, any packet not containing\n \
  SYN, RST, or ACK bits will result in a returned RST if the port is closed and\n \
  no response at all if the port is open. As long as none of those three bits\n \
  are included, any combination of the other three (FIN, PSH, and URG) are OK.\n \
  Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.\n \
  \n https://nmap.org/book/man-port-scanning-techniques.html;\
  ;xmas_scan;-sX" \
  #
  "The ACK scan probe packet has only the ACK flag set (unless you use\n \
  --scanflags). When scanning unfiltered systems, open and closed ports will\n \
  both return a RST packet. Nmap then labels them as unfiltered, meaning that\n \
  they are reachable by the ACK packet, but whether they are open or closed is\n \
  undetermined. Ports that don't respond, or send certain ICMP error messages\n \
  back (type 3, code 0, 1, 2, 3, 9, 10, or 13), are labeled filtered.\n \
  \n https://nmap.org/book/man-port-scanning-techniques.html;\
  ;tcp_ack_scan;-sA" \
  #
  "Window scan is exactly the same as ACK scan except that it exploits an\n \
  implementation detail of certain systems to differentiate open ports from\n \
  closed ones, rather than always printing unfiltered when a RST is returned. It\n \
  does this by examining the TCP Window field of the RST packets returned. On\n \
  some systems, open ports use a positive window size (even for RST packets)\n \
  while closed ones have a zero window. So instead of always listing a port as\n \
  unfiltered when it receives a RST back, Window scan lists the port as open or\n \
  closed if the TCP Window value in that reset is positive or zero,\n \
  respectively.\n \
  \n https://nmap.org/book/man-port-scanning-techniques.html;\
  ;tcp_window;-sW" \
  #
  "The Maimon scan is named after its discoverer, Uriel Maimon. He described the\n \
  technique in Phrack Magazine issue #49 (November 1996). Nmap, which included\n \
  this technique, was released two issues later. This technique is exactly the\n \
  same as NULL, FIN, and Xmas scans, except that the probe is FIN/ACK. According\n \
  to RFC 793 (TCP), a RST packet should be generated in response to such a probe\n \
  whether the port is open or closed. However, Uriel noticed that many\n \
  BSD-derived systems simply drop the packet if the port is open.\n \
  \n https://nmap.org/book/man-port-scanning-techniques.html;\
  ;tcp_maimon;-sM" \
  #
  "Protocol scan works in a similar fashion to UDP scan. Instead of iterating\n \
  through the port number field of a UDP packet, it sends IP packet headers and\n \
  iterates through the eight-bit IP protocol field. The headers are usually\n \
  empty, containing no data and not even the proper header for the claimed\n \
  protocol. The exceptions are TCP, UDP, ICMP, SCTP, and IGMP. A proper protocol\n \
  header for those is included since some systems won't send them otherwise and\n \
  because Nmap already has functions to create them. Instead of watching for\n \
  ICMP port unreachable messages, protocol scan is on the lookout for ICMP\n \
  protocol unreachable messages. If Nmap receives any response in any protocol\n \
  from the target host, Nmap marks that protocol as open. An ICMP protocol\n \
  unreachable error (type 3, code 2) causes the protocol to be marked as closed\n \
  while port unreachable (type 3, code 3) marks the protocol open. Other ICMP\n \
  unreachable errors (type 3, code 0, 1, 9, 10, or 13) cause the protocol to be\n \
  marked filtered (though they prove that ICMP is open at the same time). If no\n \
  response is received after retransmissions, the protocol is marked\n \
  open|filtered\n \
  \n https://nmap.org/book/man-port-scanning-techniques.html;\
  ;ip_proto_scan;-sO" \
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
