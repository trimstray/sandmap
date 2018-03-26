#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_version()
#
# Description:
#   NSE 'version' category module.
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
  description="NSE 'version' category module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      The scripts in this special category are an extension to the version
      detection feature and cannot be selected explicitly. They are selected to
      run only if version detection (-sV) was requested. Their output cannot be
      distinguished from version detection output and they do not produce
      service or host script results.

      URL: https://nmap.org/nsedoc/categories/version.html

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
  "Gathers information (a list of all server properties) from an AMQP (advanced\n \
  message queuing protocol) server.\n \
  \n \n https://nmap.org/nsedoc/scripts/amqp-info.html;\
  ;amqp-info;--script amqp-info -p 5672 $_cmd_params" \
  #
  "Connects to the IBM DB2 Administration Server (DAS) on TCP or UDP port 523\n \
  and exports the server profile. No authentication is required for this request.\n \
  \n \n https://nmap.org/nsedoc/scripts/db2-das-info.html;\
  ;db2-das-info;-sV -p 523 $_cmd_params" \
  #
  "Detects the Docker service version.\n \
  \n \n https://nmap.org/nsedoc/scripts/docker-version.html;\
  ;docker-version;-sV -p 2375 $_cmd_params" \
  #
  "This NSE script is used to send a EtherNet/IP packet to a remote device that\n \
  has TCP 44818 open. The script will send a Request Identity Packet and once a\n \
  response is received, it validates that it was a proper response to the\n \
  command that was sent, and then will parse out the data. Information that is\n \
  parsed includes Vendor ID, Device Type, Product name, Serial Number, Product\n \
  code, Revision Number, as well as the Device IP.\n \
  \n https://nmap.org/nsedoc/scripts/enip-info.html;\
  ;enip-info;--script enip-info -sU -p 44818 $_cmd_params" \
  #
  "Prints the readable strings from service fingerprints of unknown services.\n \
  \n https://nmap.org/nsedoc/scripts/fingerprint-strings.html;\
  ;fingerprint-strings;-sV --script fingerprint-strings $_cmd_params" \
  #
  "Retrieve hardwares details and configuration information utilizing HNAP, the\n \
  \"Home Network Administration Protocol\". It is an HTTP-Simple Object Access\n \
  Protocol (SOAP)-based protocol which allows for remote topology discovery,\n \
  configuration, and management of devices (routers, cameras, PCs, NAS, etc.)\n \
  \n https://nmap.org/nsedoc/scripts/hnap-info.html;\
  ;hnap-info;--script hnap-info -p 80,8080 $_cmd_params" \
  #
  "Uses the HTTP Server header for missing version info. This is currently\n \
  infeasible with version probes because of the need to match non-HTTP services\n \
  correctly.\n \
  \n https://nmap.org/nsedoc/scripts/http-server-header.html;\
  ;http-server-header;-sV -p 80,443,8080 $_cmd_params" \
  #
  "Obtains information (such as vendor and device type where available) from an\n \
  IKE service by sending four packets to the host. This scripts tests with both\n \
  Main and Aggressive Mode and sends multiple transforms per request.\n \
  \n https://nmap.org/nsedoc/scripts/ike-version.html;\
  ;ike-version;-sU --script ike-version -p 500 $_cmd_params" \
  #
  "Detects the Java Debug Wire Protocol. This protocol is used by Java programs\n \
  to be debugged via the network. It should not be open to the public Internet,\n \
  as it does not provide any security against malicious attackers who can inject\n \
  their own bytecode into the debugged process.\n \
  \n https://nmap.org/nsedoc/scripts/jdwp-version.html;\
  ;jdwp-version;-sV -p 9999 $_cmd_params" \
  #
  "Dumps message traffic from MQTT brokers.\n \
  \n https://nmap.org/nsedoc/scripts/mqtt-subscribe.html;\
  ;mqtt-subscribe;--script mqtt-subscribe -p 1883 $_cmd_params" \
  #
  "Retrieves version information from the remote Network Data Management\n \
  Protocol (ndmp) service. NDMP is a protocol intended to transport data between\n \
  a NAS device and the backup device, removing the need for the data to pass\n \
  through the backup server.\n \
  \n https://nmap.org/nsedoc/scripts/ndmp-version.html;\
  ;ndmp-version;-sV -p 10000 $_cmd_params" \
  #
  "Parses and displays the banner information of an OpenLookup (network\n \
  key-value store) server.\n \
  \n https://nmap.org/nsedoc/scripts/openlookup-info.html;\
  ;openlookup-info;--script openlookup-info -p 5850 $_cmd_params" \
  #
  "Detects the version of an Oracle Virtual Server Agent by fingerprinting\n \
  responses to an HTTP GET request and an XML-RPC method call.\n \
  \n https://nmap.org/nsedoc/scripts/ovs-agent-version.html;\
  ;ovs-agent-version;-sV -p 8899 $_cmd_params" \
  #
  "Attempts to extract system information from the point-to-point tunneling\n \
  protocol (PPTP) service.\n \
  \n https://nmap.org/nsedoc/scripts/pptp-version.html;\
  ;pptp-version;-sV -p 1723 $_cmd_params" \
  #
  "Retrieves the day and time from the Time service.\n \
  \n https://nmap.org/nsedoc/scripts/rfc868-time.html;\
  ;rfc868-time;-sV -p 37 $_cmd_params" \
  #
  "Fingerprints the target RPC port to extract the target service, RPC number\n \
  and version.\n \
  \n https://nmap.org/nsedoc/scripts/rpc-grind.html;\
  ;rpc-grind;--script rpc-grind --script-args 'rpc-grind.threads=8' -p 53344 $_cmd_params" \
  #
  "Connects to portmapper and fetches a list of all registered programs. It then\n \
  prints out a table including (for each program) the RPC program number,\n \
  supported version numbers, port number and protocol, and program name.\n \
  \n https://nmap.org/nsedoc/scripts/rpcinfo.html;\
  ;rpcinfo;-sV -p 111 $_cmd_params" \
  #
  "Detects the Skype version 2 service.\n \
  \n https://nmap.org/nsedoc/scripts/skypev2-version.html;\
  ;skypev2-version;-sV -p 80 $_cmd_params" \
  #
  "Extracts basic information from an SNMPv3 GET request. The same probe is used\n \
  here as in the service version detection scan.\n \
  \n https://nmap.org/nsedoc/scripts/snmp-info.html;\
  ;snmp-info;-sV -p 161 $_cmd_params" \
  #
  "Sends a binding request to the server and attempts to extract version\n \
  information from the response, if the server attribute is present.\n \
  \n https://nmap.org/nsedoc/scripts/stun-version.html;\
  ;stun-version;-sU -sV -p 3478 $_cmd_params" \
  #
  "Detects the TeamSpeak 2 voice communication server and attempts to determine\n \
  version and configuration information.\n \
  \n https://nmap.org/nsedoc/scripts/teamspeak2-version.html;\
  ;teamspeak2-version;-sU -sV -p 8767 $_cmd_params" \
  #
  "Queries VMware server (vCenter, ESX, ESXi) SOAP API to extract the version\n \
  information.\n \
  \n https://nmap.org/nsedoc/scripts/vmware-version.html;\
  ;vmware-version;--script vmware-version -p 443 $_cmd_params" \
  #
  "Connects to XMPP server (port 5222) and collects server information such as:\n \
  supported auth mechanisms, compression methods, whether TLS is supported and\n \
  mandatory, stream management, language, support of In-Band registration,\n \
  server capabilities. If possible, studies server vendor.\n \
  \n https://nmap.org/nsedoc/scripts/xmpp-info.html;\
  ;xmpp-info;-sV -p 5222 $_cmd_params"
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
