#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: broadcast()
#
# Description:
#   Broadcast Module.
#
# Usage:
#   broadcast
#
# Examples:
#   broadcast
#

function broadcast() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="broadcast"
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
  description="Broadcast Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      Broadcast Module.

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
  Attempts to discover hosts in the local network using the DNS Service\n \
  Discovery protocol and sends a NULL UDP packet to each host to test if it is\n \
  vulnerable to the Avahi NULL UDP packet denial of service (CVE-2011-1002).\n \n \
  Script Arguments:\n \n \
  - broadcast-avahi-dos.wait\n \
  Wait time in seconds before executing the check, the default value is 20 seconds.\n \n \
  - newtargets, max-newtargets, dnssd.services\n \
  See the documentation for the library.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-avahi-dos.html;\
  ;broadcast-avahi-dos;--script=broadcast-avahi-dos $params" \
  #
  "User Summary:\n \n \
  Attempts to discover DB2 servers on the network by sending a broadcast\n \
  request to port 523/udp.\n \n \
  Script Arguments:\n \n \
  - newtargets, max-newtargets, dnssd.services\n \
  See the documentation for the library.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-db2-discover.html;\
  ;broadcast-db2-discover;--script db2-discover $params" \
  #
  "User Summary:\n \n \
  Sends a DHCP request to the broadcast address (255.255.255.255) and reports\n \
  the results. The script uses a static MAC address (DE:AD:CO:DE:CA:FE) while\n \
  doing so in order to prevent scope exhaustion.\n \n \
  Script Arguments:\n \n \
  - broadcast-dhcp-discover.timeout\n \
  Time in seconds to wait for a response (default: 10s)\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-dhcp-discover.html;\
  ;broadcast-dhcp-discover;--script broadcast-dhcp-discover $params" \
  #
  "User Summary:\n \n \
  Sends a DHCPv6 request (Solicit) to the DHCPv6 multicast address, parses the\n \
  response, then extracts and prints the address along with any options returned\n \
  by the server.\n \n \
  Script Arguments:\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-dhcp6-discover.html;\
  ;broadcast-dhcp6-discover;--script broadcast-dhcp6-discover -6 $params" \
  #
  "User Summary:\n \n \
  Attempts to discover hosts' services using the DNS Service Discovery\n \
  protocol. It sends a multicast DNS-SD query and collects all the responses.\n \n \
  Script Arguments:\n \n \
  - newtargets, max-newtargets, dnssd.services\n \
  See the documentation for the library.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-dns-service-discovery.html;\
  ;broadcast-dns-service-discovery;--script=broadcast-dns-service-discovery $params" \
  #
  "User Summary:\n \n \
  Listens for the LAN sync information broadcasts that the Dropbox.com client\n \
  broadcasts every 20 seconds, then prints all the discovered client IP\n \
  addresses, port numbers, version numbers, display names, and more.\n \n \
  Script Arguments:\n \n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-dropbox-listener.html;\
  ;broadcast-dropbox-listener;--script=broadcast-dropbox-listener $params" \
  #
  "User Summary:\n \n \
  Performs network discovery and routing information gathering through Cisco's\n \
  Enhanced Interior Gateway Routing Protocol (EIGRP). The script works by\n \
  sending an EIGRP Hello packet with the specified Autonomous System value to\n \
  the 224.0.0.10 multicast address and listening for EIGRP Update packets. The\n \
  script then parses the update responses for routing information.\n \n \
  Script Arguments:\n \n \
  - broadcast-eigrp-discovery.kparams\n \
  The K metrics. Defaults to 101000.\n \
  - broadcast-eigrp-discovery.as\n \
  Autonomous System value to announce on. If not set, the script will listen\n \
  for announcements on 224.0.0.10 to grab an A.S value.\n \
  - broadcast-eigrp-discovery.interface\n \
  Interface to send on (overrides -e).\n \
  - broadcast-eigrp-discovery.timeout\n \
  Max amount of time to listen for A.S announcements and updates.\n \
  Defaults to 10 seconds.\n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \
  - -Pn\n \
  Treat all hosts as online -- skip host discovery (see discovery module).\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-eigrp-discovery.html;\
  ;broadcast-eigrp-discovery;--script=broadcast-eigrp-discovery $params" \
  #
  "User Summary:\n \n \
  Discovers targets that have IGMP Multicast memberships and grabs interesting\n \
  information. The scripts works by sending IGMP Membership Query message to the\n \
  224.0.0.1 All Hosts multicast address and listening for IGMP Membership Report\n \
  messages. The script then extracts all the interesting information from the\n \
  report messages such as the version, group, mode, source addresses (depending\n \
  on the version).\n \n \
  Script Arguments:\n \n \
  - broadcast-igmp-discovery.mgroupnamesdb:\n \
  Database with multicast group names\n \
  - broadcast-igmp-discovery.version\n \
  IGMP version to use. Could be 1, 2, 3 or all. Defaults to 2\n \
  - broadcast-igmp-discovery.timeout\n \
  Time to wait for reports in seconds. Defaults to 5 seconds\n \
  - broadcast-igmp-discovery.interface\n \
  Network interface to use\n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \
  - -e <interface>\n \
  Use specified interface.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-igmp-discovery.html;\
  ;broadcast-igmp-discovery;--script broadcast-igmp-discovery $params" \
  #
  "User Summary:\n \n \
  Sniffs the network for incoming broadcast communication and attempts to decode\n \
  the received packets. It supports protocols like CDP, HSRP, Spotify, DropBox,\n \
  DHCP, ARP and a few more. See packetdecoders.lua for more information.\n \n \
  Script Arguments:\n \n \
  - broadcast-listener.timeout\n \
  Specifies the amount of seconds to sniff the network interface (default 30s).\n \
  - -e <interface>\n \
  Use specified interface.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-listener.html;\
  ;broadcast-listener;--script broadcast-listener $params" \
  #
  "User Summary:\n \n \
  Discovers Microsoft SQL servers in the same broadcast domain. SQL Server\n \
  credentials required: No (will not benefit from mssql.username &\n \
  mssql.password).\n \n \
  Script Arguments:\n \n \
  - mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port,\n \
  mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username\n \
  See the documentation for the mssql library.\n \
  - randomseed, smbbasic, smbport, smbsign\n \
  See the documentation for the smb library.\n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-ms-sql-discover.html;\
  ;broadcast-ms-sql-discover;--script broadcast-ms-sql-discover $params" \
  #
  "User Summary:\n \n \
  Attempts to discover master browsers and the domains they manage.\n \n \
  Script Arguments:\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-netbios-master-browser.html;\
  ;broadcast-netbios-master-browser;--script=broadcast-netbios-master-browser $params" \
  #
  "User Summary:\n \n \
  Attempts to use the Service Location Protocol to discover Novell NetWare\n \
  Core Protocol (NCP) servers.\n \n \
  Script Arguments:\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-novell-locate.html;\
  ;broadcast-novell-locate;--script=broadcast-novell-locate -sV $params" \
  #
  "User Summary:\n \n \
  Discover IPv4 networks using Open Shortest Path First version 2(OSPFv2) protocol.\n \
  The script works by listening for OSPF Hello packets from the 224.0.0.5 multicast\n \
  address. The script then replies and attempts to create a neighbor relationship,\n \
  in order to discover network database.\n \n \
  Script Arguments:\n \n \
  - broadcast-ospf2-discover.md5_key\n \
  MD5 digest key to use if message digest authentication is disclosed.\n \
  - broadcast-ospf2-discover.router_id\n \
  Router ID to use. Defaults to 0.0.0.1.\n \
  - broadcast-ospf2-discover.timeout\n \
  Time in seconds that the script waits for hello from other routers.\n \
  Defaults to 10 seconds, matching OSPFv2 default value for hello interval.\n \
  - broadcast-ospf2-discover.interface\n \
  Interface to send on (overrides -e). Mandatory if not using -e and multiple\n \
  interfaces are present.\n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \
  - -e <interface>\n \
  Use specified interface.\n \
  \n --script=broadcast-ospf2-discover;\
  ;broadcast-ospf2-discover;--script db2-discover $params" \
  #
  "User Summary:\n \n \
  Sends broadcast pings on a selected interface using raw ethernet packets and\n \
  outputs the responding hosts' IP and MAC addresses or (if requested) adds them\n \
  as targets. Root privileges on UNIX are required to run this script since it\n \
  uses raw sockets. Most operating systems don't respond to broadcast-ping\n \
  probes, but they can be configured to do so. The interface on which is\n \
  broadcasted can be specified using the -e Nmap option or the\n \
  broadcast-ping.interface script-arg. If no interface is specified this script\n \
  broadcasts on all ethernet interfaces which have an IPv4 address defined.\n \n \
  Script Arguments:\n \n \
  - broadcast-ping.timeout\n \
  Timespec specifying how long to wait for response (default 3s).\n \
  - broadcast-ping.num_probes\n \
  Number specifying how many ICMP probes should be sent (default 1).\n \
  - broadcast-ping.interface\n \
  String specifying which interface to use for this script (default all interfaces).\n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \
  - -e <interface>\n \
  Use specified interface.\n \
  - --ttl <val>\n \
  Set IP time-to-live field.\n \
  - --data-length <num>\n \
  Append random data to sent packets.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-ping.html;\
  ;broadcast-ping;--script broadcast-ping $params" \
  #
  "User Summary:\n \n \
  Discovers PPPoE (Point-to-Point Protocol over Ethernet) servers using the\n \
  PPPoE Discovery protocol (PPPoED). PPPoE is an ethernet based protocol so the\n \
  script has to know what ethernet interface to use for discovery. If no\n \
  interface is specified, requests are sent out on all available interfaces.\n \n \
  Script Arguments:\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-pppoe-discover.html;\
  ;broadcast-pppoe-discover;--script broadcast-pppoe-discover $params" \
  #
  "User Summary:\n \n \
  Discovers hosts and routing information from devices running RIPv2 on the LAN.\n \
  It does so by sending a RIPv2 Request command and collects the responses from\n \
  all devices responding to the request.\n \n \
  Script Arguments:\n \n \
  - broadcast-rip-discover.timeout\n \
  Timespec defining how long to wait for a response. (default 5s).\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-rip-discover.html;\
  ;broadcast-rip-discover;--script broadcast-rip-discover $params" \
  #
  "User Summary:\n \n \
  Discovers hosts and routing information from devices running RIPng on the LAN by\n \
  sending a broadcast RIPng Request command and collecting any responses.\n \n \
  Script Arguments:\n \n \
  - broadcast-ripng-discover.timeout\n \
  Sets the connection timeout (default: 5s)\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-ripng-discover.html;\
  ;broadcast-ripng-discover;--script broadcast-ripng-discover $params" \
  #
  "User Summary:\n \n \
  Attempts to extract system information from the UPnP service by sending\n \
  a multicast query, then collecting, parsing, and displaying all responses.\n \n \
  Script Arguments:\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-upnp-info.html;\
  ;broadcast-upnp-info;--script=broadcast-upnp-info -sV $params" \
  #
  "User Summary:\n \n \
  Attempts to extract system information from the UPnP service by sending\n \
  a multicast query, then collecting, parsing, and displaying all responses.\n \n \
  Script Arguments:\n \n \
  - broadcast-wake-on-lan.address\n \
  The broadcast address to which the WoL packet is sent.\n \
  - broadcast-wake-on-lan.MAC\n \
  The MAC address of the remote system to wake up.\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-db2-discover.html;\
  ;broadcast-wake-on-lan;--script broadcast-wake-on-lan $params" \
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
