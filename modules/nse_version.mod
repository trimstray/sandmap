#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_version()
#
# Description:
#   NSE Version category module.
#
# Usage:
#   nse_version
#
# Examples:
#   nse_version
#

function nse_version() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_version"
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
  description="NSE Version category module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE Version category module.

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

  # shellcheck disable=SC2034
  _module_commands=(\
  #
  "Detects the All-Seeing Eye service;\
  -p 27015;allseeingeye-info;-Pn -sU -sV --script allseeingeye-info -p 27015)" \
  #
  "Gathers info from an AMQP;\
  -p 5672;amqp-info;--script amqp-info -p 5672" \
  #
  "Discovers and enumerates BACNet Devices;\
  -p 47808;bacnet-info;--script bacnet-info -sU -p 47808" \
  #
  "Detects the CCcam service;\
  -p 12000;cccam-version;-sV -p 12000" \
  #
  "Connects to the IBM DB2;\
  -p 523;db2-das-info;-sV -p 523" \
  #
  "Detects the Docker service;\
  -p 2375;docker-version;-sV -p 2375" \
  #
  "Extract info from DB with the DRDA proto;\
  -p 50000;drda-info;-sV -p 50000" \
  #
  "Send a EtherNet/IP packet;\
  -p 44818;enip-info;--script enip-info -sU -p 44818" \
  #
  "Prints strings from unknown services;\
  ;fingerprint-strings;-sV --script fingerprint-strings" \
  #
  "Tridium Niagara Fox protocol;\
  -p 1911;fox-info;--script fox-info.nse -p 1911" \
  #
  "Detects the Freelancer game server, FLServer.exe;\
  -p 2302;freelancer-info;-sU --script=freelancer-info -p 2302" \
  #
  "Retrieve hardwares and config details utilizing HNAP;\
  -p 80,8080;hnap-info;--script hnap-info -p 80,8080" \
  #
  "Uses the HTTP Server header for missing version info;\
  -p 80,443,8080;http-server-header;-sV -p 80,443,8080" \
  #
  "Attempts to obtain info from Trane Tracer SC devices;\
  -p 80;http-trane-info;--script trane-info.nse -p 80" \
  #
  "Detects the UDP IAX2 service;\
  -p 4569;iax2-version;-sU -sV -p 4569" \
  #
  "Obtains info (such as vendor and device) from an IKE;\
  -p 500;ike-version;-sU --script ike-version -p 500" \
  #
  "Detects the Java Debug Wire Protocol;\
  -p 9999;jdwp-version;-sV -p 9999" \
  #
  "Retrieves version and db info from a SAP Max DB;\
  -p 7210;maxdb-info;--script maxdb-info -p 7210" \
  #
  "Check if ePO agent is running on ePO Agent port;\
  -p 8081;mcafee-epo-agent;-sV -p 8081" \
  #
  "Dumps message traffic from MQTT brokers;\
  -p 1883;mqtt-subscribe;--script mqtt-subscribe -p 1883" \
  #
  "Detects the Murmur service;\
  -p 64740;murmur-version;-sV -p 64740" \
  #
  "Retrieves version info from NDMP service;\
  ;ndmp-version;-sV -p $port" \
  #
  "Extends version detection to detect NetBuster;\
  -p 12345;netbus-version;-sV --script netbus-version -p 12345" \
  #
  "Send a FINS packet to a remote device;\
  -p 9600;omron-info;--script omron-info -sU -p 9600" \
  #
  "Parses and displays the banner info of an OpenLookup;\
  -p 5850;openlookup-info;--script openlookup-info -p 5850" \
  #
  "Decodes the VSNNUM version number (Oracle TNS listener);\
  ;oracle-tns-version;-sV -p $port" \
  #
  "Detects the version of an Oracle Virtual Server Agent;\
  -p 8899;ovs-agent-version;-sV -p 8899" \
  #
  "Attempts to extract system info from the PPTP;\
  -p 1723;pptp-version;-sV -p 1723" \
  #
  "Extracts info from Quake game servers;\
  U:26000-26004;quake1-info;-n -sU -Pn --script quake1-info -p U:26000-26004" \
  #
  "Extracts info from a Quake3 game server;\
  -p 27960;quake3-info;-sU -sV -Pn --script quake3-info.nse -p 27960" \
  #
  "Retrieves the day and time from the Time service;\
  -p 37;rfc868-time;-sV -p 37" \
  #
  "Fingerprints the target RPC port to extract the target;\
  -p 53344;rpc-grind;--script rpc-grind --script-args 'rpc-grind.threads=8' -p 53344" \
  #
  "Connects to portmapper and fetches a list of all programs;\
  -p 111;rpcinfo;-sV -p 111" \
  #
  "Enumerates Siemens S7 PLC Devices and collects device info;\
  -p 102;s7-info;--script s7-info.nse -p 102" \
  #
  "Detects the Skype version 2 service;\
  -p 80;skypev2-version;-sV -p 80" \
  #
  "Extracts basic info from an SNMPv3 GET request;\
  -p 161;snmp-info;-sV -p 161" \
  #
  "Sends req to the server and get info from the res;\
  -p 3478;stun-version;-sU -sV -p 3478" \
  #
  "Detects the TeamSpeak 2;\
  -p 8767;teamspeak2-version;-sU -sV -p 8767" \
  #
  "Detects the Ventrilo voice communication server;\
  -p 9408;ventrilo-info;-Pn -sU -sV --script ventrilo-info -p 9408" \
  #
  "Queries VMware server (vCenter, ESX, ESXi) SOAP API;\
  -p 443;vmware-version;--script vmware-version -p 443" \
  #
  "Detects vulns and gathers info from VxWorks Wind DeBug;\
  -p 17185;wdb-version;-sU --script wdb-version -p 17185" \
  #
  "Detect the T3 RMI protocol and Weblogic version;\
  ;weblogic-t3-info;-sV -p $port" \
  #
  "Connects to XMPP server and collects server info;\
  -p 5222;xmpp-info;-sV -p 5222"
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
