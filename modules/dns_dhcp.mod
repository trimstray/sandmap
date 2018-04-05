#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: dns_dhcp()
#
# Description:
#   DNS and DHCP Module.
#
# Usage:
#   dns_dhcp
#
# Examples:
#   dns_dhcp
#

function dns_dhcp() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="dns_dhcp"
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
  description="DNS and DHCP Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      DNS and DHCP Module.

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
  Maps IP addresses to autonomous system (AS) numbers. The script works by\n \
  sending DNS TXT queries to a DNS server which in turn queries a third-party\n \
  service provided by Team Cymru\n \
  (https://www.team-cymru.org/Services/ip-to-asn.html) using an in-addr.arpa\n \
  style zone set up especially for use by Nmap. The responses to these queries\n \
  contain both Origin and Peer ASNs and their descriptions, displayed along with\n \
  the BGP Prefix and Country Code. The script caches results to reduce the\n \
  number of queries and should perform a single query for all scanned targets in\n \
  a BGP Prefix present in Team Cymru's database.\n \n \
  Script Arguments:\n \n \
  - dns\n \
  The address of a recursive nameserver to use (optional).\n \
  \n https://nmap.org/nsedoc/scripts/asn-query.html;\
  ;asn-query;--script asn-query $params" \
  #
  "User Summary:\n \n \
  Checks target IP addresses against multiple DNS anti-spam and open proxy\n \
  blacklists and returns a list of services for which an IP has been flagged.\n \
  Checks may be limited by service category (eg: SPAM, PROXY) or to a specific\n \
  service name.\n \n \
  Script Arguments:\n \n \
  - dns-blacklist.services\n \
  String containing a comma-separated list of services to query (default: all).\n \n \
  - dns-blacklist.ip\n \
  String containing the IP to check only needed if running the script as a prerule.\n \n \
  - dns-blacklist.list\n \
  Lists all services that are available for a certain category.\n \n \
  - dns-blacklist.category\n \
  String containing the service category to query eg. spam or proxy (default: all).\n \n \
  - dns-blacklist.services\n \
  String containing either \"short\" or \"long\" long mode can sometimes provide\n \
  additional information to why an IP has been blacklisted. (default: long).\n \n \
  - -sn\n \
  Ping Scan - disable port scan.\n \
  \n https://nmap.org/nsedoc/scripts/dns-blacklist.html;\
  ;dns-blacklist;--script dns-blacklist $params" \
  #
  "User Summary:\n \n \
  Attempts to enumerate DNS hostnames by brute force guessing of common\n \
  subdomains. With the dns-brute.srv argument, dns-brute will also try to\n \
  enumerate common DNS SRV records. Wildcard records are listed as \"*A\" and\n \
  \"*AAAA\" for IPv4 and IPv6 respectively.\n \n \
  Script Arguments:\n \n \
  - dns-brute.threads\n \
  Thread to use (default 5).\n \n \
  - dns-brute.srvlist\n \
  The filename of a list of SRV records to try. Defaults to \"nselib/data/dns-srv-names\".\n \n \
  - dns-brute.hostlist\n \
  The filename of a list of host strings to try. Defaults to \"nselib/data/vhosts-default.lst\".\n \n \
  - dns-brute.srv\n \
  Perform lookup for SRV records.\n \n \
  - dns-brute.domain\n \
  Domain name to brute force if no host is specified.\n \n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \n \
  - -sS\n \
  TCP SYN scan.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 80).\n \
  \n https://nmap.org/nsedoc/scripts/dns-brute.html;\
  ;dns-brute;--script dns-brute $params" \
  #
  "User Summary:\n \n \
  Performs DNS cache snooping against a DNS server. There are two modes of\n \
  operation, controlled by the dns-cache-snoop.mode script argument. In\n \
  nonrecursive mode (the default), queries are sent to the server with the RD\n \
  (recursion desired) flag set to 0. The server should respond positively to\n \
  these only if it has the domain cached. In timed mode, the mean and standard\n \
  deviation response times for a cached domain are calculated by sampling the\n \
  resolution of a name (www.google.com) several times. Then, each domain is\n \
  resolved and the time taken compared to the mean. If it is less than one\n \
  standard deviation over the mean, it is considered cached. The timed mode\n \
  inserts entries in the cache and can only be used reliably once.\n \n \
  Script Arguments:\n \n \
  - dns-cache-snoop.mode\n \
  Which of two supported snooping methods to use. nonrecursive, the default,\n \
  checks if the server returns results for non-recursive queries. Some servers\n \
  may disable this. timed measures the difference in time taken to resolve\n \
  cached and non-cached hosts. This mode will pollute the DNS cache and can only\n \
  be used once reliably.\n \n \
  - dns-cache-snoop.domains\n \
  An array of domain to check in place of the default list.\n \n \
  - -sU\n \
  UDP Scan.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 53).\n \
  \n https://nmap.org/nsedoc/scripts/dns-cache-snoop.html;\
  ;dns-cache-snoop;--script dns-cache-snoop.nse $params" \
  #
  "User Summary:\n \n \
  Checks DNS zone configuration against best practices, including RFC 1912. The\n \
  configuration checks are divided into categories which each have a number of\n \
  different tests.\n \n \
  Script Arguments:\n \n \
  - dns-check-zone.domain\n \
  The dns zone to check.\n \n \
  - -sn\n \
  Ping Scan - disable port scan.\n \n \
  - -Pn\n \
  Treat all hosts as online -- skip host discovery.\n \
  \n https://nmap.org/nsedoc/scripts/dns-check-zone.html;\
  ;dns-check-zone;--script dns-check-zone $params" \
  #
  "User Summary:\n \n \
  Performs a domain lookup using the edns-client-subnet option which allows\n \
  clients to specify the subnet that queries supposedly originate from. The\n \
  script uses this option to supply a number of geographically distributed\n \
  locations in an attempt to enumerate as many different address records as\n \
  possible. The script also supports requests using a given subnet.\n \n \
  Script Arguments:\n \n \
  - dns-client-subnet-scan.domain\n \
  The domain to lookup eg. www.example.org.\n \n \
  - dns-client-subnet-scan.mask\n \
  The number of bits to use as subnet mask (default: 24).\n \n \
  - dns-client-subnet-scan.nameserver\n \
  Nameserver to use (default = host.ip).\n \n \
  - dns-client-subnet-scan.address\n \
  The client subnet address to use.\n \n \
  - -sU\n \
  UDP Scan.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 53).\n \
  \n https://nmap.org/nsedoc/scripts/dns-client-subnet-scan.html;\
  ;dns-client-subnet-scan;--script dns-client-subnet-scan $params" \
  #
  "User Summary:\n \n \
  Launches a DNS fuzzing attack against DNS servers. The script induces errors\n \
  into randomly generated but valid DNS packets. The packet template that we use\n \
  includes one uncompressed and one compressed name.\n \n \
  Script Arguments:\n \n \
  - dns-fuzz.timelimit\n \
  How long to run the fuzz attack. This is a number followed by a suffix: s for\n \
  seconds, m for minutes, and h for hours. Use 0 for an unlimited amount of\n \
  time. Default: 10m.\n \n \
  - -sU\n \
  UDP Scan.\n \n \
  \n https://nmap.org/nsedoc/scripts/dns-fuzz.html;\
  ;dns-fuzz;--script dns-fuzz $params" \
  #
  "User Summary:\n \n \
  Performs a quick reverse DNS lookup of an IPv6 network using a technique which\n \
  analyzes DNS server response codes to dramatically reduce the number of\n \
  queries needed to enumerate large networks. The technique essentially works by\n \
  adding an octet to a given IPv6 prefix and resolving it. If the added octet is\n \
  correct, the server will return NOERROR, if not a NXDOMAIN result is received.\n \n \
  Script Arguments:\n \n \
  - prefix\n \
  The ip6 prefix to scan.\n \n \
  - mask\n \
  The ip6 mask to start scanning from.\n \
  \n https://nmap.org/nsedoc/scripts/dns-ip6-arpa-scan.html;\
  ;dns-ip6-arpa-scan;--script dns-ip6-arpa-scan $params" \
  #
  "User Summary:\n \n \
  Enumerates DNS names using the DNSSEC NSEC-walking technique. Output is\n \
  arranged by domain. Within a domain, subzones are shown with increased\n \
  indentation.\n \n \
  Script Arguments:\n \n \
  - dns-nsec-enum.domains\n \
  The domain or list of domains to enumerate. If not provided, the script will\n \
  make a guess based on the name of the target.\n \n \
  - -sU\n \
  UDP Scan.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 53).\n \
  \n https://nmap.org/nsedoc/scripts/dns-nsec-enum.html;\
  ;dns-nsec-enum;--script dns-nsec-enum $params" \
  #
  "User Summary:\n \n \
  Tries to enumerate domain names from the DNS server that supports DNSSEC NSEC3\n \
  records. The script queries for nonexistant domains until it exhausts all\n \
  domain ranges keeping track of hashes. At the end, all hashes are printed\n \
  along with salt and number of iterations used. This technique is known as\n \
  \"NSEC3 walking\".\n \n \
  Script Arguments:\n \n \
  - dns-nsec3-enum.domains\n \
  The domain or list of domains to enumerate. If not provided, the script will\n \
  make a guess based on the name of the target.\n \n \
  - dns-nsec3-enum.timelimit\n \
  Sets a script run time limit. Default 30 minutes.\n \n \
  - -sU\n \
  UDP Scan.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 53).\n \
  \n https://nmap.org/nsedoc/scripts/dns-nsec3-enum.html;\
  ;dns-nsec3-enum;--script=dns-nsec3-enum $params" \
  #
  "User Summary:\n \n \
  Retrieves information from a DNS nameserver by requesting its nameserver ID\n \
  (nsid) and asking for its id.server and version.bind values. This script\n \
  performs the same queries as the following two dig commands: - dig CH TXT\n \
  bind.version @target - dig +nsid CH TXT id.server @target.\n \n \
  Script Arguments:\n \n \
  - -sU\n \
  UDP Scan.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 53).\n \
  \n https://nmap.org/nsedoc/scripts/dns-nsid.html;\
  ;dns-nsid;--script dns-nsid $params" \
  #
  "User Summary:\n \n \
  Checks a DNS server for the predictable-port recursion vulnerability.\n \
  Predictable source ports can make a DNS server vulnerable to cache poisoning\n \
  attacks (see CVE-2008-1447).\n \n \
  Script Arguments:\n \n \
  - -sU\n \
  UDP Scan.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 53).\n \
  \n https://nmap.org/nsedoc/scripts/dns-random-srcport.html;\
  ;dns-random-srcport;--script=dns-random-srcport $params" \
  #
  "User Summary:\n \n \
  Checks a DNS server for the predictable-TXID DNS recursion vulnerability.\n \
  Predictable TXID values can make a DNS server vulnerable to cache poisoning\n \
  attacks (see CVE-2008-1447).\n \n \
  Script Arguments:\n \n \
  - -sU\n \
  UDP Scan.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 53).\n \
  \n https://nmap.org/nsedoc/scripts/dns-random-txid.html;\
  ;dns-random-txid;--script=dns-random-txid $params" \
  #
  "User Summary:\n \n \
  Checks if a DNS server allows queries for third-party names. It is expected\n \
  that recursion will be enabled on your own internal nameservers.\n \n \
  Script Arguments:\n \n \
  - -sU\n \
  UDP Scan.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 53).\n \
  \n https://nmap.org/nsedoc/scripts/dns-recursion.html;\
  ;dns-recursion;--script=dns-recursion $params" \
  #
  "User Summary:\n \n \
  Attempts to discover target hosts' services using the DNS Service Discovery\n \
  protocol.\n \n \
  Script Arguments:\n \n \
  - newtargets, max-newtargets, dnssd.services\n \
  See the documentation for the library.\n \
  \n https://nmap.org/nsedoc/scripts/dns-service-discovery.html;\
  ;dns-service-discovery;--script=dns-service-discovery $params" \
  #
  "User Summary:\n \n \
  Enumerates various common service (SRV) records for a given domain name. The\n \
  service records contain the hostname, port and priority of servers for a given\n \
  service. The following services are enumerated by the script: - Active\n \
  Directory Global Catalog - Exchange Autodiscovery - Kerberos KDC Service -\n \
  Kerberos Passwd Change Service - LDAP Servers - SIP Servers - XMPP S2S - XMPP\n \
  C2S.\n \n \
  Script Arguments:\n \n \
  - dns-srv-enum.domain\n \
  String containing the domain to query\n \n \
  - dns-srv-enum.filter\n \
  String containing the service to query (default: all).\n \n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \
  \n https://nmap.org/nsedoc/scripts/dns-srv-enum.html;\
  ;dns-srv-enum;--script dns-srv-enum $params" \
  #
  "User Summary:\n \n \
  Gathers information (a list of all server properties) from an AMQP\n \
  (advanced message queuing protocol) server.\n \n \
  Script Arguments:\n \n \
  - dns-update.test\n \
  Add and remove 4 records to determine if the target is vulnerable.\n \n \
  - dns-update.ip\n \
  The ip address of the host to add to the zone.\n \n \
  - dns-update.hostname\n \
  The name of the host to add to the zone.\n \n \
  - -sU\n \
  UDP Scan.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 53).\n \
  \n https://nmap.org/nsedoc/scripts/dns-update.html;\
  ;dns-update;--script=dns-update $params" \
  #
  "User Summary:\n \n \
  Requests a zone transfer (AXFR) from a DNS server. The script sends an AXFR\n \
  query to a DNS server. The domain to query is determined by examining the name\n \
  given on the command line, the DNS server's hostname, or it can be specified\n \
  with the dns-zone-transfer.domain script argument. If the query is successful\n \
  all domains and domain types are returned along with common type specific data\n \
  (SOA/MX/NS/PTR/A).\n \n \
  Script Arguments:\n \n \
  - dns-zone-transfer.port\n \
  DNS server port, this argument concerns the \"Script Pre-scanning phase\" and\n \
  it's optional, the default value is 53.\n \n \
  - dns-zone-transfer.server\n \
  DNS server. If set, this argument will enable the script for the \"Script Pre-scanning phase\".\n \n \
  - dns-zone-transfer.domain\n \
  Domain to transfer.\n \n \
  - dns-zone-transfer.addall\n \
  If specified, adds all IP addresses including private ones onto Nmap scanning\n \
  queue when the script argument newtargets is given. The default behavior is to\n \
  skip private IPs (non-routable).\n \n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \
  \n https://nmap.org/nsedoc/scripts/dns-zone-transfer.html;\
  ;dns-zone-transfer;--script dns-zone-transfer.nse $params" \
  #
  "User Summary:\n \n \
  Performs a Forward-confirmed Reverse DNS lookup and reports anomalous\n \
  results.\n \n \
  Script Arguments:\n \n \
  - -sn\n \
  Ping Scan - disable port scan.\n \n \
  - -Pn\n \
  Treat all hosts as online -- skip host discovery.\n \
  \n https://nmap.org/nsedoc/scripts/fcrdns.html;\
  ;fcrdns;--script fcrdns $params" \
  #
  "User Summary:\n \n \
  Discovers hostnames that resolve to the target's IP address by querying the\n \
  online database at http://www.bfk.de/bfk_dnslogger.html. The script is in the\n \
  \"external\" category because it sends target IPs to a third party in order to\n \
  query their database.\n \n \
  Script Arguments:\n \n \
  - hostmap-bfk.prefix\n \
  If set, saves the output for each host in a file called \"<prefix><target>\".\n \
  The file contains one entry per line.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \
  \n https://nmap.org/nsedoc/scripts/hostmap-bfk.html;\
  ;hostmap-bfk;--script hostmap-bfk $params" \
  #
  "User Summary:\n \n \
  Finds subdomains of a web server by querying Google's Certificate Transparency\n \
  logs database (https://crt.sh). The script will run against any target that\n \
  has a name, either specified on the command line or obtained via\n \
  reverse-DNS.\n \n \
  Script Arguments:\n \n \
  - hostmap.prefix\n \
  If set, saves the output for each host in a file called \"<prefix><target>\".\n \
  The file contains one entry per line.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \n \
  - -sn\n \
  Ping Scan - disable port scan.\n \
  \n https://nmap.org/nsedoc/scripts/hostmap-crtsh.html;\
  ;hostmap-crtsh;--script hostmap-crtsh $params" \
  #
  "User Summary:\n \n \
  Finds hostnames that resolve to the target's IP address by querying the online\n \
  database: http://www.ip2hosts.com (Bing Search Results).\n \
  The script is in the \"external\" category because it sends target IPs to a\n \
  third party in order to query their database.\n \n \
  Script Arguments:\n \n \
  - hostmap.prefix\n \
  If set, saves the output for each host in a file called \"<prefix><target>\".\n \
  The file contains one entry per line.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \n \
  - -sn\n \
  Ping Scan - disable port scan.\n \
  \n https://nmap.org/nsedoc/scripts/hostmap-ip2hosts.html;\
  ;hostmap-ip2hosts;--script hostmap-ip2hosts $params" \
  #
  "User Summary:\n \n \
  Discovers hostnames that resolve to the target's IP address by querying the\n \
  online Robtex service at http://ip.robtex.com/.\n \n \
  Script Arguments:\n \n \
  - hostmap.prefix\n \
  If set, saves the output for each host in a file called \"<prefix><target>\".\n \
  The file contains one entry per line.\n \n \
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
  \n https://nmap.org/nsedoc/scripts/hostmap-robtex.html;\
  ;hostmap-robtex;--script hostmap-robtex $params" \
  #
  "User Summary:\n \n \
  Resolves a hostname by using the LLMNR (Link-Local Multicast Name Resolution)\n \
  protocol. The script works by sending a LLMNR Standard Query containing the\n \
  hostname to the 5355 UDP port on the 224.0.0.252 multicast address. It listens\n \
  for any LLMNR responses that are sent to the local machine with a 5355 UDP\n \
  source port. A hostname to resolve must be provided.\n \n \
  Script Arguments:\n \n \
  - llmnr-resolve.timeout\n \
  Max time to wait for a response (default 3s).\n \n \
  - llmnr-resolve.hostname\n \
  Hostname to resolve.\n \n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \n \
  \n https://nmap.org/nsedoc/scripts/llmnr-resolve.html;\
  ;llmnr-resolve;--script llmnr-resolve $params" \
  #
  "User Summary:\n \n \
  Resolves hostnames and adds every address (IPv4 or IPv6, depending on Nmap\n \
  mode) to Nmap's target list. This differs from Nmap's normal host resolution\n \
  process, which only scans the first address (A or AAAA record) returned for\n \
  each host name.\n \n \
  Script Arguments:\n \n \
  - resolveall.hosts\n \
  Table of hostnames to resolve.\n \n \
  - newtargets, max-newtargets\n \
  See the documentation for the library.\n \n \
  \n https://nmap.org/nsedoc/scripts/resolveall.html;\
  ;resolveall;--script=resolveall $params" \
  "User Summary:\n \n \
  Sends a DHCPINFORM request to a host on UDP port 67 to obtain all the local\n \
  configuration parameters without allocating a new address. DHCPINFORM is a\n \
  DHCP request that returns useful information from a DHCP server, without\n \
  allocating an IP address. The request sends a list of which fields it wants to\n \
  know (a handful by default, every field if verbosity is turned on), and the\n \
  server responds with the fields that were requested. It should be noted that\n \
  the server doesn't have to return every field, nor does it have to return them\n \
  in the same order, or honour the request at all. A Linksys WRT54g, for\n \
  example, completely ignores the list of requested fields and returns a few\n \
  standard ones. This script displays every field it receives.\n \n \
  Script Arguments:\n \n \
  - randomize_mac\n \
  Set to true or 1 to send a random MAC address with the request (keep in mind\n \
  that you may not see the response). This should cause the router to reserve a\n \
  new IP address each time.\n \n \
  - requests\n \
  Set to an integer to make up to that many requests (and display the results).\n \n \
  - dhcptype\n \
  The type of DHCP request to make. By default, DHCPINFORM is sent, but this\n \
  argument can change it to DHCPOFFER, DHCPREQUEST, DHCPDECLINE, DHCPACK,\n \
  DHCPNAK, DHCPRELEASE or DHCPINFORM. Not all types will evoke a response from\n \
  all servers, and many require different fields to contain specific values.\n \n \
  - -sU\n \
  UDP Scan.\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 67).\n \
  \n https://nmap.org/nsedoc/scripts/dhcp-discover.html;\
  ;dhcp-discover;--script=dhcp-discover $params" \
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
