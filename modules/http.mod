#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: http()
#
# Description:
#   HTTP Module.
#
# Usage:
#   http
#
# Examples:
#   http
#

function http() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="http"
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
  description="HTTP Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      HTTP Module.

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
  Grabs affiliate network IDs (e.g. Google AdSense or Analytics, Amazon\n \
  Associates, etc.) from a web page. These can be used to identify pages with\n \
  the same owner. If there is more than one target using an ID, the postrule of\n \
  this script shows the ID along with a list of the targets using it.\n \n \
  Script Arguments:\n \n \
  - http-affiliate-id.url-path\n \
  The path to request. Defaults to /.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-affiliate-id.html;\
  ;http-affiliate-id;--script=http-affiliate-id.nse $params" \
  #
  "User Summary:\n \n \
  Checks if the target http server has mod_negotiation enabled. This feature can\n \
  be leveraged to find hidden resources and spider a web site using fewer\n \
  requests. The script works by sending requests for resources like index and\n \
  home without specifying the extension. If mod_negotiate is enabled (default\n \
  Apache configuration), the target would reply with content-location header\n \
  containing target resource (such as index.html) and vary header containing\n \
  \"negotiate\" depending on the configuration.\n \n \
  Script Arguments:\n \n \
  - http-apache-negotiation.root\n \
  Target web site root. Defaults to /.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-apache-negotiation.html;\
  ;http-apache-negotiation;--script=http-apache-negotiation $params" \
  #
  "User Summary:\n \n \
  Attempts to retrieve the server-status page for Apache webservers that have\n \
  mod_status enabled. If the server-status page exists and appears to be from\n \
  mod_status the script will parse useful information such as the system uptime,\n \
  Apache version and recent HTTP requests.\n \n \
  Script Arguments:\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-apache-server-status.html;\
  ;http-apache-server-status;--script http-apache-server-status $params" \
  #
  "User Summary:\n \n \
  Determines if a ASP.NET application has debugging enabled using a HTTP DEBUG\n \
  request. The HTTP DEBUG verb is used within ASP.NET applications to start/stop\n \
  remote debugging sessions. The script sends a 'stop-debug' command to\n \
  determine the application's current configuration state but access to RPC\n \
  services is required to interact with the debugging session. The request does\n \
  not change the application debugging configuration.\n \n \
  Script Arguments:\n \n \
  - http-aspnet-debug.path\n \
  Path to URI. Default: /.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-aspnet-debug.html;\
  ;http-aspnet-debug;--script http-aspnet-debug $params" \
  #
  "User Summary:\n \n \
  Retrieves the authentication scheme and realm of a web service that requires\n \
  authentication.\n \n \
  Script Arguments:\n \n \
  - http-auth.path\n \
  Define the request path.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-auth.html;\
  ;http-auth;--script http-auth $params" \
  #
  "User Summary:\n \n \
  Spiders a web site to find web pages requiring form-based or HTTP-based\n \
  authentication. The results are returned in a table with each url and the\n \
  detected method.\n \n \
  Script Arguments:\n \n \
  - http-auth-finder.url\n \
  Rhe url to start spidering. This is a URL relative to the scanned host eg.\n \
  /default.html (default: /).\n \n \
  - http-auth-finder.maxdepth\n \
  The maximum amount of directories beneath the initial url to spider. A\n \
  negative value disables the limit. (default: 3).\n \n \
  - http-auth-finder.maxpagecount\n \
  The maximum amount of pages to visit. A negative value disables the limit\n \
  (default: 20).\n \n \
  - http-auth-finder.withinhost\n \
  Only spider URLs within the same host. (default: true).\n \n \
  - http-auth-finder.withindomain\n \
  Only spider URLs within the same domain. This widens the scope from withinhost\n \
  and can not be used in combination. (default: false).\n \n \
  - httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount,\n \
  httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,\n \
  httpspider.withindomain, httpspider.withinhost\n \
  See the documentation for the httpspider library.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-auth-finder.html;\
  ;http-auth-finder;--script http-auth-finder $params" \
  #
  "User Summary:\n \n \
  Exploits a remote code execution vulnerability in Awstats Totals 1.0 up to\n \
  1.14 and possibly other products based on it (CVE: 2008-3922). This\n \
  vulnerability can be exploited through the GET variable sort. The script\n \
  queries the web server with the command payload encoded using PHP's chr()\n \
  function: ?sort={%24{passthru%28chr(117).chr(110).chr(97).chr(109).chr(101).chr(32).chr(45).chr(97)%29}}{%24{exit%28%29}}\n \n \
  Script Arguments:\n \n \
  - http-awstatstotals-exec.uri\n \
  Awstats Totals URI including path. Default: /index.php.\n \n \
  - http-awstatstotals-exec.cmd\n \
  Command to execute. Default: whoami.\n \n \
  - http-awstatstotals-exec.outfile\n \
  Output file. If set it saves the output in this file.\n \n \
  - http.useragent\n \
  User Agent to use in GET request.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-awstatstotals-exec.html;\
  ;http-awstatstotals-exec;--script http-awstatstotals-exec.nse $params" \
  #
  "User Summary:\n \n \
  Spiders a website and attempts to identify backup copies of discovered files.\n \
  It does so by requesting a number of different combinations of the filename\n \
  (eg. index.bak, index.html~, copy of index.html).\n \n \
  Script Arguments:\n \n \
  - http-backup-finder.maxpagecount\n \
  The maximum amount of pages to visit. A negative value disables the limit\n \
  (default: 20).\n \n \
  - http-backup-finder.withindomain\n \
  Only spider URLs within the same domain. This widens the scope from withinhost\n \
  and can not be used in combination. (default: false).\n \n \
  - http-backup-finder.maxdepth\n \
  The maximum amount of directories beneath the initial url to spider. A\n \
  negative value disables the limit. (default: 3).\n \n \
  - http-backup-finder.url\n \
  The url to start spidering. This is a URL relative to the scanned host eg.\n \
  /default.html (default: /).\n \n \
  - http-backup-finder.withinhost\n \
  Only spider URLs within the same host. (default: true).\n \n \
  - httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount,\n \
  httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,\n \
  httpspider.withindomain, httpspider.withinhost\n \
  See the documentation for the httpspider library.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-backup-finder.html;\
  ;http-backup-finder;--script=http-backup-finder $params" \
  #
  "User Summary:\n \n \
  Decodes any unencrypted F5 BIG-IP cookies in the HTTP response. BIG-IP cookies\n \
  contain information on backend systems such as internal IP addresses and port\n \
  numbers.\n \n \
  Script Arguments:\n \n \
  - http-bigip-cookie.path\n \
  The URL path to request. The default path is \"/\".\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-bigip-cookie.html;\
  ;http-bigip-cookie;--script http-bigip-cookie $params" \
  #
  "User Summary:\n \n \
  Performs brute force password auditing against http basic, digest and ntlm\n \
  authentication. This script uses the unpwdb and brute libraries to perform\n \
  password guessing. Any successful guesses are stored in the nmap registry,\n \
  using the creds library, for other scripts to use.\n \n \
  Script Arguments:\n \n \
  - http-brute.hostname\n \
  Sets the host header in case of virtual hosting.\n \n \
  - http-brute.method\n \
  Sets the HTTP method to use (default: GET).\n \n \
  - http-brute.path\n \
  Points to the path protected by authentication (default: /).\n \n \
  - creds.[service], creds.global\n \
  See the documentation for the creds library.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \n \
  - passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb\n \
  See the documentation for the unpwdb library.\n \n \
  - brute.credfile, brute.delay, brute.emptypass, brute.firstonly,\n \
  brute.guesses, brute.mode, brute.passonly, brute.retries, brute.start,\n \
  brute.threads, brute.unique, brute.useraspass\n \
  See the documentation for the brute library.\n \
  \n https://nmap.org/nsedoc/scripts/http-brute.html;\
  ;http-brute;--script http-brute $params" \
  #
  "User Summary:\n \n \
  Obtains the CakePHP version of a web application built with the CakePHP\n \
  framework by fingerprinting default files shipped with the CakePHP framework.\n \
  This script queries the files 'vendors.php', 'cake.generic.css',\n \
  'cake.icon.png and 'cake.icon.gif' to try to obtain the version of the CakePHP\n \
  installation.\n \n \
  Script Arguments:\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-cakephp-version.html;\
  ;http-cakephp-version;--script http-cakephp-version $params" \
  #
  "User Summary:\n \n \
  Measures the time a website takes to deliver a web page and returns the\n \
  maximum, minimum and average time it took to fetch a page. Web pages that take\n \
  longer time to load could be abused by attackers in DoS or DDoS attacks due to\n \
  the fact that they are likely to consume more resources on the target server.\n \
  This script could help identifying these web pages.\n \n \
  Script Arguments:\n \n \
  - http-chrono.tries\n \
  The number of times to fetch a page based on which max, min and average\n \
  calculations are performed.\n \n \
  - http-chrono.withindomain\n \
  Only spider URLs within the same domain. This widens the scope from withinhost\n \
  and can not be used in combination. (default: false).\n \n \
  - http-chrono.withinhost\n \
  Only spider URLs within the same host. (default: true).\n \n \
  - http-chrono.maxdepth\n \
  The maximum amount of directories beneath the initial url to spider. A\n \
  negative value disables the limit. (default: 3).\n \n \
  - http-chrono.maxpagecount\n \
  The maximum amount of pages to visit. A negative value disables the limit \n \
  (default: 1).\n \n \
  - http-chrono.url\n \
  The url to start spidering. This is a URL relative to the scanned host eg.\n \
  /default.html (default: /).\n \n \
  - httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount,\n \
  httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,\n \
  httpspider.withindomain, httpspider.withinhost\n \
  See the documentation for the httpspider library.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-chrono.html;\
  ;http-chrono;--script http-chrono $params" \
  #
  "User Summary:\n \n \
  Gathers information (a list of all server properties) from an AMQP\n \
  (advanced message queuing protocol) server.\n \n \
  Script Arguments:\n \n \
  - http-comments-displayer.singlepages\n \
  Some single pages to check for comments. For example, {\"/\", \"/wiki\"}.\n \
  Default: nil (crawler mode on)\n \n \
  - http-comments-displayer.context\n \
  Declares the number of chars to extend our final strings. This is useful when\n \
  we need to to see the code that the comments are referring to. Default: 0,\n \
  Maximum Value: 50.\n \n \
  - httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount,\n \
  httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,\n \
  httpspider.withindomain, httpspider.withinhost\n \
  See the documentation for the httpspider library.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-comments-displayer.html;\
  ;http-comments-displayer;--script http-comments-displayer $params" \
  #
  "User Summary:\n \n \
  Checks for backups and swap files of common content management system and web\n \
  server configuration files.\n \n \
  Script Arguments:\n \n \
  - http-config-backup.save\n \
  Directory to save all the valid config files found.\n \n \
  - http-config-backup.path\n \
  The path where the CMS is installed.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-config-backup.html;\
  ;http-config-backup;--script=http-config-backup $params" \
  #
  "User Summary:\n \n \
  Examines cookies set by HTTP services. Reports any session cookies set without\n \
  the httponly flag. Reports any session cookies set over SSL without the secure\n \
  flag. If http-enum.nse is also run, any interesting paths found by it will be\n \
  checked in addition to the root.\n \n \
  Script Arguments:\n \n \
  - cookie\n \
  Specific cookie name to check flags on. Default: A variety of commonly used\n \
  session cookie names and patterns.\n \n \
  - path\n \
  Specific URL path to check for session cookie flags. Default: / and those\n \
  found by http enum.\n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-cookie-flags.html;\
  ;http-cookie-flags;--script http-cookie-flags $params" \
  #
  "User Summary:\n \n \
  Tests an http server for Cross-Origin Resource Sharing (CORS), a way for\n \
  domains to explicitly opt in to having certain methods invoked by another\n \
  domain. The script works by setting the Access-Control-Request-Method header\n \
  field for certain enumerated methods in OPTIONS requests, and checking the\n \
  responses.\n \n \
  Script Arguments:\n \n \
  - http-cors.path\n \
  The path to request. Defaults to /.\n \n \
  - http-cors.origin\n \
  The origin used with requests. Defaults to example.com.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-cors.html;\
  ;http-cors;--script http-cors $params" \
  #
  "User Summary:\n \n \
  Checks the cross-domain policy file (/crossdomain.xml) and the\n \
  client-acces-policy file (/clientaccesspolicy.xml) in web applications and\n \
  lists the trusted domains. Overly permissive settings enable Cross Site\n \
  Request Forgery attacks and may allow attackers to access sensitive data. This\n \
  script is useful to detect permissive configurations and possible domain names\n \
  available for purchase to exploit the application. The script queries\n \
  instantdomainsearch.com to lookup the domains. This functionality is turned\n \
  off by default, to enable it set the script argument\n \
  http-cross-domain-policy.domain-lookup.\n \n \
  Script Arguments:\n \n \
  - http-cross-domain-policy.domain-lookup\n \
  Boolean to check domain availability. Default:false.\n \n \
  - vulns.short, vulns.showall\n \
  See the documentation for the vulns library.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-cross-domain-policy.html;\
  ;http-cross-domain-policy;--script http-cross-domain-policy $params" \
  #
  "User Summary:\n \n \
  This script detects Cross Site Request Forgeries (CSRF) vulnerabilities. It\n \
  will try to detect them by checking each form if it contains an unpredictable\n \
  token for each user. Without one an attacker may forge malicious requests. To\n \
  recognize a token in a form, the script will iterate through the form's\n \
  attributes and will search for common patterns in their names. If that fails,\n \
  it will also calculate the entropy of each attribute's value. A big entropy\n \
  means a possible token.\n \n \
  Script Arguments:\n \n \
  - http-csrf.singlepages\n \
  The pages that contain the forms to check. For example, {/upload.php,\n \
  /login.php}. Default: nil (crawler mode on).\n \n \
  - http-csrf.checkentropy\n \
  If this is set the script will also calculate the entropy of the field's value\n \
  to determine if it is a token, rather than just checking its name. Default:\n \
  true.\n \n \
  - httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount,\n \
  httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,\n \
  httpspider.withindomain, httpspider.withinhost\n \
  See the documentation for the httpspider library.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/amqp-info.html;\
  ;http-csrf;--script http-csrf $params" \
  #
  "User Summary:\n \n \
  Gets the date from HTTP-like services. Also prints how much the date differs\n \
  from local time. Local time is the time the HTTP request was sent, so the\n \
  difference includes at least the duration of one RTT.\n \n \
  Script Arguments:\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-date.html;\
  ;http-date;--script=http-date $params" \
  #
  "User Summary:\n \n \
  Tests for access with default credentials used by a variety of web\n \
  applications and devices. It works similar to http-enum, we detect\n \
  applications by matching known paths and launching a login routine using\n \
  default credentials when found. This script depends on a fingerprint file\n \
  containing the target's information: name, category, location paths, default\n \
  credentials and login routine.\n \n \
  Script Arguments:\n \n \
  - http-default-accounts.category\n \
  Selects a category of fingerprints to use.\n \n \
  - http-default-accounts.fingerprintfile\n \
  Fingerprint filename. Default: http-default-accounts-fingerprints.lua.\n \n \
  - http-default-accounts.basepath\n \
  Base path to append to requests. Default: \"/\".\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  - creds.[service], creds.global\n \
  See the documentation for the creds library.\n \
  \n https://nmap.org/nsedoc/scripts/http-default-accounts.html;\
  ;http-default-accounts;--script http-default-accounts $params" \
  #
  "User Summary:\n \n \
  Tries to find out the technology behind the target website. The script checks\n \
  for certain defaults that might not have been changed, like common headers or\n \
  URLs or HTML content. While the script does some guessing, note that overall\n \
  there's no way to determine what technologies a given site is using. You can\n \
  help improve this script by adding new entries to nselib/data/http-devframework-fingerprints.lua\n \n \
  Script Arguments:\n \n \
  - http-devframework.fingerprintfile\n \
  File containing fingerprints. Default: nselib/data/http-devframework-fingerprints.lua\n \n \
  - http-devframework.rapid\n \
  Boolean value that determines if a rapid detection should take place. The main\n \
  difference of a rapid vs a lengthy detection is that second one requires\n \
  crawling through the website. Default: false (lengthy detection is performed).\n \n \
  - httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount,\n \
  httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,\n \
  httpspider.withindomain, httpspider.withinhost\n \
  See the documentation for the httpspider library.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-devframework.html;\
  ;http-devframework;--script http-devframework $params" \
  #
  "User Summary:\n \n \
  Detects a firmware backdoor on some D-Link routers by changing the User-Agent\n \
  to a \"secret\" value. Using the \"secret\" User-Agent bypasses authentication and\n \
  allows admin access to the router. The following router models are likely to\n \
  be vulnerable: DIR-100, DIR-120, DI-624S, DI-524UP, DI-604S, DI-604UP,\n \
  DI-604+, TM-G5240\n \n \
  Script Arguments:\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \n \
  - vulns.short, vulns.showall\n \
  See the documentation for the vulns library.\n \
  \n https://nmap.org/nsedoc/scripts/http-dlink-backdoor.html;\
  ;http-dlink-backdoor;--script http-dlink-backdoor $params" \
  #
  "User Summary:\n \n \
  It looks for places where attacker-controlled information in the DOM may be\n \
  used to affect JavaScript execution in certain ways.\n \n \
  Script Arguments:\n \n \
  - http-dombased-xss.singlepages\n \
  The pages to test. For example, {/index.php, /profile.php}. Default: nil\n \
  (crawler mode on).\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \n \
  - httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount,\n \
  httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,\n \
  httpspider.withindomain, httpspider.withinhost\n \
  See the documentation for the httpspider library.\n \
  \n https://nmap.org/nsedoc/scripts/http-dombased-xss.html;\
  ;http-dombased-xss;--script http-dombased-xss $params" \
  #
  "User Summary:\n \n \
  Enumerates the installed Drupal modules/themes by using a list of known\n \
  modules and themes. The script works by iterating over module/theme names and\n \
  requesting MODULE_PATH/MODULE_NAME/LICENSE.txt for modules and\n \
  THEME_PATH/THEME_NAME/LICENSE.txt. MODULE_PATH/THEME_PATH which is either\n \
  provided by the user, grepped for in the html body or defaulting to\n \
  sites/all/modules/.\n \n \
  Script Arguments:\n \n \
  - http-drupal-enum.themes_path\n \
  Direct Path for Themes.\n \n \
  - http-drupal-enum.number\n \
  Number of modules to check. Use this option with a number or \"all\" as an\n \
  argument to test for all modules. Defaults to 100.\n \n \
  - http-drupal-enum.type\n \
  Default all.choose between \"themes\" and \"modules\".\n \n \
  - http-drupal-enum.root\n \
  The base path. Defaults to /.\n \n \
  - http-drupal-enum.modules_path\n \
  Direct Path for Modules.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-drupal-enum.html;\
  ;http-drupal-enum;--script http-drupal-enum $params" \
  #
  "User Summary:\n \n \
  Enumerates Drupal users by exploiting an information disclosure vulnerability\n \
  in Views, Drupal's most popular module. Requests to\n \
  admin/views/ajax/autocomplete/user/STRING return all usernames that begin with\n \
  STRING. The script works by iterating STRING over letters to extract all\n \
  usernames.\n \n \
  Script Arguments:\n \n \
  - http-drupal-enum-users.root\n \
  Base path. Defaults to \"/\".\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \n \
  \n https://nmap.org/nsedoc/scripts/http-drupal-enum-users.html;\
  ;http-drupal-enum-users;--script=http-drupal-enum-users $params" \
  #
  "User Summary:\n \n \
  This script crawls through the website and returns any error pages. The script\n \
  will return all pages (sorted by error code) that respond with an http code\n \
  equal or above 400. To change this behaviour, please use the errcodes option.\n \
  The script, by default, spiders and searches within forty pages. For large web\n \
  applications make sure to increase httpspider's maxpagecount value. Please,\n \
  note that the script will become more intrusive though.\n \n \
  Script Arguments:\n \n \
  - http-errors.errcodes\n \
  The error codes we are interested in. Default: nil (all codes >= 400).\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \n \
  - httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount,\n \
  httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,\n \
  httpspider.withindomain, httpspider.withinhost\n \
  See the documentation for the httpspider library.\n \
  \n https://nmap.org/nsedoc/scripts/http-errors.html;\
  ;http-errors;--script http-errors $params" \
  #
  "User Summary:\n \n \
  Exploits insecure file upload forms in web applications using various\n \
  techniques like changing the Content-type header or creating valid image files\n \
  containing the payload in the comment.\n \n \
  Script Arguments:\n \n \
  - http-fileupload-exploiter.fieldvalues\n \
  The script will try to fill every field found in the upload form but that may\n \
  fail due to fields' restrictions. You can manually fill those fields using\n \
  this table. For example, {gender = \"male\", email = \"foo@bar.com\"}. Default:\n \
  {}\n \n \
  - http-fileupload-exploiter.formpaths\n \
  The pages that contain the forms to exploit. For example, {/upload.php,\n \
  /login.php}. Default: nil (crawler mode on).\n \n \
  - http-fileupload-exploiter.uploadspaths\n \
  Directories with the uploaded files. For example, {/avatars, /photos}.\n \
  Default: {'/uploads', '/upload', '/file', '/files', '/downloads'}.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \n \
  - httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount,\n \
  httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,\n \
  httpspider.withindomain, httpspider.withinhost\n \
  See the documentation for the httpspider library.\n \
  \n https://nmap.org/nsedoc/scripts/http-fileupload-exploiter.html;\
  ;http-fileupload-exploiter;--script http-fileupload-exploiter $params" \
  #
  "User Summary:\n \n \
  Performs brute force password auditing against http form-based authentication.\n \
  This script uses the unpwdb and brute libraries to perform password guessing.\n \
  Any successful guesses are stored in the nmap registry, using the creds\n \
  library, for other scripts to use. The script automatically attempts to\n \
  discover the form method, action, and field names to use in order to perform\n \
  password guessing. (Use argument path to specify the page where the form\n \
  resides.) If it fails doing so the form components can be supplied using\n \
  arguments method, path, uservar, and passvar. The same arguments can be used\n \
  to selectively override the detection outcome. The script contains a small\n \
  database of known web apps' form information. This improves form detection and\n \
  also allows for form mangling and custom success detection functions. If the\n \
  script arguments aren't expressive enough, users are encouraged to edit the\n \
  database to fit. After attempting to authenticate using a HTTP GET or POST\n \
  request the script analyzes the response and attempts to determine whether\n \
  authentication was successful or not.\n \n \
  Script Arguments:\n \n \
  - http-form-brute.hostname\n \
  Sets the host header in case of virtual hosting.\n \n \
  - http-form-brute.path\n \
  Identifies the page that contains the form (default: \"/\"). The script\n \
  analyses the content of this page to determine the form destination, method,\n \
  and fields. If argument passvar is specified then the form detection is not\n \
  performed and the path argument is instead used as the form submission\n \
  destination (the form action). Use the other arguments to define the rest of\n \
  the form manually as necessary.\n \n \
  - http-form-brute.onfailure\n \
  Sets the message/pattern to expect on unsuccessful authentication\n \
  (optional).\n \n \
  - http-form-brute.sessioncookies\n \
  Attempt to grab session cookies before submitting the form. Setting this to\n \
  \"false\" could speed up cracking against forms that do not require any cookies\n \
  to be set before logging in. Default: true.\n \n \
  - http-form-brute.passvar\n \
  Sets the http-variable name that holds the password used to authenticate. If\n \
  this argument is set then the form detection is not performed. Use the other\n \
  arguments to define the form manually.\n \n \
  - http-form-brute.onsuccess\n \
  Sets the message/pattern to expect on successful authentication (optional).\n \n \
  - http-form-brute.uservar\n \
  Sets the form field name that holds the username used to authenticate.\n \n \
  - http-form-brute.method\n \
  Sets the HTTP method (default: \"POST\").\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \n \
  - creds.[service], creds.global\n \
  See the documentation for the creds library.\n \
  - passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb\n \
  See the documentation for the unpwdb library.\n \n \
  - brute.credfile, brute.delay, brute.emptypass, brute.firstonly,\n \
  brute.guesses, brute.mode, brute.passonly, brute.retries, brute.start,\n \
  brute.threads, brute.unique, brute.useraspass\n \
  See the documentation for the brute library.\n \
  \n https://nmap.org/nsedoc/scripts/http-form-brute.html;\
  ;http-form-brute;--script http-form-brute $params" \
  #
  "User Summary:\n \n \
  Performs a simple form fuzzing against forms found on websites. Tries strings\n \
  and numbers of increasing length and attempts to determine if the fuzzing was\n \
  successful.\n \n \
  Script Arguments:\n \n \
  - http-form-fuzzer.minlength\n \
  The minimum length of a string that will be used for fuzzing, defaults to\n \
  300000.\n \n \
  - http-form-fuzzer.maxlength\n \
  The maximum length of a string that will be used for fuzzing, defaults to\n \
  310000.\n \n \
  - http-form-fuzzer.targets\n \
  A table with the targets of fuzzing, for example {{path = /index.html,\n \
  minlength = 40002}, {path = /foo.html, maxlength = 10000}}. The path parameter\n \
  is required, if minlength or maxlength is not specified, then the values of\n \
  http-form-fuzzer.minlength or http-form-fuzzer.maxlength will be used.\n \
  Defaults to {{path=\"/\"}}.\n \n \
  - httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount,\n \
  httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,\n \
  httpspider.withindomain, httpspider.withinhost\n \
  See the documentation for the httpspider library.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-form-fuzzer.html;\
  ;http-form-fuzzer;--script http-form-fuzzer $params" \
  #
  "User Summary:\n \n \
  Gathers information (a list of all server properties) from an AMQP\n \
  (advanced message queuing protocol) server.\n \n \
  Script Arguments:\n \n \
  - http-frontpage-login.path\n \
  Path prefix to Frontpage directories. Defaults to root (\"/\").\n \n \
  - vulns.short, vulns.showall\n \
  See the documentation for the vulns library.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-frontpage-login.html;\
  ;http-frontpage-login;--script=http-frontpage-login $params" \
  #
  "User Summary:\n \n \
  Checks for a Git repository found in a website's document root\n \
  /.git/<something>) and retrieves as much repo information as possible,\n \
  including language/framework, remotes, last commit message, and repository\n \
  description.\n \n \
  Script Arguments:\n \n \
  - http-git.root\n \
  URL path to search for a .git directory. Default: /.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-git.html;\
  ;http-git;--script http-git $params" \
  #
  "User Summary:\n \n \
  Spiders a website and attempts to match all pages and urls against a given\n \
  string. Matches are counted and grouped per url under which they were\n \
  discovered. Features built in patterns like email, ip, ssn, discover, amex and\n \
  more. The script searches for email and ip by default.\n \n \
  Script Arguments:\n \n \
  - http-grep.breakonmatch\n \
  Returns output if there is a match for a single pattern type.\n \n \
  - http-grep.builtins\n \
  Supply a single or a list of built in types. supports email, phone,\n \
  mastercard, discover, visa, amex, ssn and ip addresses. If you just put in\n \
  script-args http-grep.builtins then all will be enabled.\n \
  - http-grep.maxdepth\n \
  The maximum amount of directories beneath the initial url to spider. A\n \
  negative value disables the limit. (default: 3).\n \n \
  - http-grep.withinhost\n \
  Only spider URLs within the same host. (default: true).\n \n \
  - http-grep.withindomain\n \
  Only spider URLs within the same domain. This widens the scope from withinhost\n \
  and can not be used in combination. (default: false).\n \n \
  - http-grep.match\n \
  The string to match in urls and page contents or list of patterns separated by\n \
  delimiter.\n \n \
  - http-grep.maxpagecount\n \
  The maximum amount of pages to visit. A negative value disables the limit\n \
  (default: 20).\n \n \
  - http-grep.url\n \
  The url to start spidering. This is a URL relative to the scanned host eg.\n \
  /default.html (default: /).\n \n \
  - httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount,\n \
  httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,\n \
  httpspider.withindomain, httpspider.withinhost\n \
  See the documentation for the httpspider library.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-grep.html;\
  ;http-grep;--script http-grep $params" \
  #
  "User Summary:\n \n \
  Performs a HEAD request for the root folder (\"/\") of a web server and displays\n \
  the HTTP headers returned.\n \n \
  Script Arguments:\n \n \
  - useget\n \
  Set to force GET requests instead of HEAD.\n \n \
  - path\n \
  The path to request, such as /index.php. Default /.\n \n \
  - slaxml.debug\n \
  See the documentation for the slaxml library.\n \n \
  - http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent\n \
  See the documentation for the http library.\n \n \
  - smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername\n \
  See the documentation for the smbauth library.\n \
  \n https://nmap.org/nsedoc/scripts/http-headers.html;\
  ;http-headers;--script=http-headers $params" \
  #
  "User Summary:\n \n \
  Gathers information (a list of all server properties) from an AMQP\n \
  (advanced message queuing protocol) server.\n \n \
  Script Arguments:\n \n \
  - amqp.version\n \
  Can be used to specify the client version to use\n \
  (currently, 0-8, 0-9 or 0-9-1).\n \n \
  - -p <port>\n \
  Only scan specified ports (for this: 5672).\n \
  \n https://nmap.org/nsedoc/scripts/amqp-info.html;\
  ;amqp-info;--script amqp-info $params" \
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
