#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_broadcast()
#
# Description:
#   NSE 'broadcast' category module.
#
# Usage:
#   nse_broadcast
#
# Examples:
#   nse_broadcast
#

function nse_broadcast() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_broadcast"
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
  description="NSE 'broadcast' category module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Scripts in this category typically do discovery of hosts not listed on the
      command line by broadcasting on the local network. Use the newtargets
      script argument to allow these scripts to automatically add the hosts they
      discover to the Nmap scanning queue.

      URL: https://nmap.org/nsedoc/categories/discovery.html

    Commands
    --------

      help                            display module help
      show    <key>                   display module or profile info
      config  <key>                   show module configuration
      set     <key>                   set module variable value
      use     <module>                reuse module (changed env)
      pushd   <key>|init|show|flush   command line commands stack

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
  "Performs a HEAD or GET request against either the root directory or any\n \
  optional directory of an Apache JServ Protocol server and returns the server\n \
  response headers.\n \
  \n https://nmap.org/nsedoc/scripts/ajp-headers.html;\
  ;ajp-headers;--script ajp-headers -p 8009 $_cmd_params" \
  #
  "Requests a URI over the Apache JServ Protocol and displays the result (or\n \
  stores it in a file). Different AJP methods such as: GET, HEAD, TRACE, PUT or\n \
  DELETE may be used.\n \
  \n https://nmap.org/nsedoc/scripts/ajp-request.html;\
  ;ajp-request;--script ajp-request -p 8009 $_cmd_params" \
  #
  "Gathers information (a list of all server properties) from an AMQP (advanced\n \
  message queuing protocol) server.\n \
  \n https://nmap.org/nsedoc/scripts/amqp-info.html;\
  ;amqp-info;--script amqp-info -p 5672 $_cmd_params" \
  #
  "Maps IP addresses to autonomous system (AS) numbers.\n \
  \n https://nmap.org/nsedoc/scripts/asn-query.html;\
  ;asn-query;--script asn-query [--script-args dns=<DNS server>] $_cmd_params" \
  #
  "A simple banner grabber which connects to an open TCP port and prints out\n \
  anything sent by the listening service within five seconds.\n \
  \n https://nmap.org/nsedoc/scripts/banner.html;\
  ;banner;-sV --script=banner $_cmd_params" \
  #
  "Discovers bittorrent peers sharing a file based on a user-supplied torrent\n \
  file or magnet link. Peers implement the Bittorrent protocol and share the\n \
  torrent, whereas the nodes (only shown if the include-nodes NSE argument is\n \
  given) implement the DHT protocol and are used to track the peers. The sets of\n \
  peers and nodes are not the same, but they usually intersect.\n \
  \n https://nmap.org/nsedoc/scripts/bittorrent-discovery.html;\
  ;bittorrent-discovery;--script bittorrent-discovery --script-args newtargets,bittorrent-discovery.torrent=<torrent_file> $_cmd_params" \
  #
  "Performs network discovery and routing information gathering through Cisco's\n \
  Enhanced Interior Gateway Routing Protocol EIGRP).\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-eigrp-discovery.html;\
  ;broadcast-eigrp-discovery-1;--script=broadcast-eigrp-discovery $_cmd_params" \
  #
  "Performs network discovery and routing information gathering through Cisco's\n \
  Enhanced Interior Gateway Routing Protocol EIGRP).\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-eigrp-discovery.html;\
  ;broadcast-eigrp-discovery-2;--script=broadcast-eigrp-discovery -e eth0 $_cmd_params" \
  #
  "Discovers targets that have IGMP Multicast memberships and grabs interesting\n \
  information.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-igmp-discovery.html;\
  ;broadcast-igmp-discovery-1;--script broadcast-igmp-discovery $_cmd_params" \
  #
  "Discovers targets that have IGMP Multicast memberships and grabs interesting\n \
  information.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-igmp-discovery.html;\
  ;broadcast-igmp-discovery-2;--script broadcast-igmp-discovery -e eth0 $_cmd_params" \
  #
  "Discovers targets that have IGMP Multicast memberships and grabs interesting\n \
  information.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-igmp-discovery.html;\
  ;broadcast-igmp-discovery-3;--script broadcast-igmp-discovery --script-args 'broadcast-igmp-discovery.version=all, broadcast-igmp-discovery.timeout=3' $_cmd_params" \
  #
  "Discover IPv4 networks using Open Shortest Path First version 2(OSPFv2)\n \
  protocol.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-ospf2-discover.html;\
  ;broadcast-ospf2-discover;--script=broadcast-ospf2-discover $_cmd_params" \
  #
  "Sends broadcast pings on a selected interface using raw ethernet packets and\n \
  outputs the responding hosts' IP and MAC addresses or (if requested) adds them\n \
  as targets. Root privileges on UNIX are required to run this script since it\n \
  uses raw sockets. Most operating systems don't respond to broadcast-ping\n \
  probes, but they can be configured to do so.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-ping.html;\
  ;broadcast-ping;-e <interface> [--ttl <ttl>] [--data-length <payload_length>] --script broadcast-ping [--script-args [broadcast-ping.timeout=<ms>],[num-probes=<n>]] $_cmd_params" \
  #
  "Attempts to get basic info and server status from a Cassandra database.\n \
  \n https://nmap.org/nsedoc/scripts/cassandra-info.html;\
  ;cassandra-info;--script=cassandra-info -p 9160 $_cmd_params" \
  #
  "Extracts a list of published applications from the ICA Browser service.\n \
  \n https://nmap.org/nsedoc/scripts/citrix-enum-apps.html;\
  ;citrix-enum-apps;-sU --script=citrix-enum-apps -p 1604 $_cmd_params" \
  #
  "Extracts a list of applications, ACLs, and settings from the Citrix XML\n \
  service.\n \
  \n https://nmap.org/nsedoc/scripts/citrix-enum-apps-xml.html;\
  ;citrix-enum-apps-xml;--script=citrix-enum-apps-xml -p 80,443,8080 $_cmd_params" \
  #
  "Extracts a list of Citrix servers from the ICA Browser service.\n \
  \n https://nmap.org/nsedoc/scripts/citrix-enum-servers.html;\
  ;citrix-enum-servers;-sU --script=citrix-enum-servers -p 1604 $_cmd_params" \
  #
  "Extracts the name of the server farm and member servers from Citrix XML\n \
  service.\n \
  \n https://nmap.org/nsedoc/scripts/citrix-enum-servers-xml.html;\
  ;citrix-enum-servers-xml;--script=citrix-enum-servers-xml -p 80,443,8080 $_cmd_params" \
  #
  "Gets database tables from a CouchDB database.\n \
  \n https://nmap.org/nsedoc/scripts/couchdb-databases.html;\
  ;couchdb-databases;--script \"couchdb-databases.nse\" -p 5984 $_cmd_params" \
  #
  "Gets database statistics from a CouchDB database.\n \
  \n https://nmap.org/nsedoc/scripts/asn-query.html;\
  ;couchdb-stats;--script \"couchdb-stats.nse\" -p 5984  $_cmd_params" \
  #
  "Lists printers managed by the CUPS printing service.\n \
  \n https://nmap.org/nsedoc/scripts/cups-info.html;\
  ;cups-info;--script cups-info -p 631 $_cmd_params" \
  #
  "Lists currently queued print jobs of the remote CUPS service grouped by\n \
  printer.\n \
  \n https://nmap.org/nsedoc/scripts/cups-queue-info.html;\
  ;cups-queue-info;--script cups-queue-info -p 631 $_cmd_params" \
  #
  "Connects to the IBM DB2 Administration Server (DAS) on TCP or UDP port 523\n \
  and exports the server profile. No authentication is required for this request.\n \
  \n https://nmap.org/nsedoc/scripts/db2-das-info.html;\
  ;db2-das-info;-sV -p 523 $_cmd_params" \
  #
  "Sends a DHCPINFORM request to a host on UDP port 67 to obtain all the local\n \
  configuration parameters without allocating a new address.\n \
  \n https://nmap.org/nsedoc/scripts/dhcp-discover.html;\
  ;dhcp-discover;-sU --script=dhcp-discover -p 67 $_cmd_params" \
  #
  "Attempts to enumerate DNS hostnames by brute force guessing of common\n \
  subdomains. With the dns-brute.srv argument, dns-brute will also try to\n \
  enumerate common DNS SRV records.\n \
  \n https://nmap.org/nsedoc/scripts/dns-brute.html;\
  ;dns-brute-1;--script dns-brute $_cmd_params" \
  #
  "Attempts to enumerate DNS hostnames by brute force guessing of common\n \
  subdomains. With the dns-brute.srv argument, dns-brute will also try to\n \
  enumerate common DNS SRV records.\n \
  \n https://nmap.org/nsedoc/scripts/dns-brute.html;\
  ;dns-brute-2;--script dns-brute --script-args dns-brute.domain=foo.com,dns-brute.threads=6,dns-brute.hostlist=./hostfile.txt,newtargets -sS -p 80 $_cmd_params" \
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
