#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_vuln()
#
# Description:
#   NSE Vuln category module.
#
# Usage:
#   nse_vuln
#
# Examples:
#   nse_vuln
#

function nse_vuln() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_vuln"
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
  description="NSE Vuln category module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      These scripts check for specific known vulnerabilities
      and generally only report results if they are found.

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
  "Detects the Mac OS X AFP directory traversal vulnerability, CVE-2010-0533. \n \n https://nmap.org/nsedoc/scripts/afp-path-vuln.html;\
  -p 548;afp-path-vuln;-sV --script=afp-path-vuln -p 548" \
  #
  "Attempts to discover hosts in the local network using the DNS Service Discovery protocol\n and sends a NULL UDP packet to each host to test if it is vulnerable to the Avahi NULL UDP\n packet denial of service (CVE-2011-1002). \n \n https://nmap.org/nsedoc/scripts/broadcast-avahi-dos.html;\
  ;broadcast-avahi-dos;--script=broadcast-avahi-dos" \
  #
  "Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution (1). \n \n https://nmap.org/nsedoc/scripts/clamav-exec.html;\
  ;clamav-exec-1;-sV --script clamav-exec" \
  #
  "Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution (2). \n \n https://nmap.org/nsedoc/scripts/clamav-exec.html;\
  ;clamav-exec-2;--script clamav-exec --script-args cmd='scan',scandb='files.txt'" \
  #
  "Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution (3). \n \n https://nmap.org/nsedoc/scripts/clamav-exec.html;\
  ;clamav-exec-3;--script clamav-exec --script-args cmd='shutdown'" \
  #
  "Detects and exploits a remote code execution vulnerability in the distributed compiler\n daemon distcc. The vulnerability was disclosed in 2002, but is still present in modern implementation\n due to poor configuration of the service. \n \n https://nmap.org/nsedoc/scripts/distcc-cve2004-2687.html;\
  ;distcc-cve2004-2687;--script distcc-exec --script-args=\"distcc-exec.cmd='id'\" -p 3632" \
  # Script Arguments
  "Attempts to perform a dynamic DNS update without authentication. \n \n https://nmap.org/nsedoc/scripts/dns-update.html;\
  ;dns-update;-sU --script=dns-update --script-args=dns-update.hostname=foo.example.com,dns-update.ip=192.0.2.1 -p 53" \
  # Script Arguments
  "Detects a vulnerability in netfilter and other firewalls that use helpers to dynamically\n open ports for protocols such as ftp and sip (1). \n \n https://nmap.org/nsedoc/scripts/firewall-bypass.html;\
  ;firewall-bypass-1;--script firewall-bypass" \
  # Script Arguments
  "Detects a vulnerability in netfilter and other firewalls that use helpers to dynamically\n open ports for protocols such as ftp and sip (2). \n \n https://nmap.org/nsedoc/scripts/firewall-bypass.html;\
  ;firewall-bypass-2;--script firewall-bypass --script-args firewall-bypass.helper=\"ftp\", firewall-bypass.targetport=22" \
  #
  "Checks if an FTPd is prone to CVE-2010-1938 (OPIE off-by-one stack overflow), a vulnerability\n discovered by Maksymilian Arciemowicz and Adam \"pi3\" Zabrocki. See the advisory at\n https://nmap.org/r/fbsd-sa-opie. Be advised that, if launched against a vulnerable host,\n this script will crash the FTPd.\n \n https://nmap.org/nsedoc/scripts/ftp-libopie.html;\
  ;ftp-libopie;-sV --script=ftp-libopie" \
  # Script Arguments
  "Tests for the presence of the ProFTPD 1.3.3c backdoor reported as OSVDB-ID 69562.\n This script attempts to exploit the backdoor using the innocuous id command by default,\n but that can be changed with the ftp-proftpd-backdoor.cmd script argument.\n \n https://nmap.org/nsedoc/scripts/ftp-proftpd-backdoor.html;\
  ;ftp-proftpd-backdoor;--script ftp-proftpd-backdoor -p 21" \
  # Script Arguments
  "Tests for the presence of the vsFTPd 2.3.4 backdoor reported on 2011-07-04 (CVE-2011-2523).\n This script attempts to exploit the backdoor using the innocuous id command by default,\n but that can be changed with the exploit.cmd or ftp-vsftpd-backdoor.cmd script arguments. \n \n https://nmap.org/nsedoc/scripts/ftp-vsftpd-backdoor.html;\
  ;ftp-vsftpd-backdoor;--script ftp-vsftpd-backdoor -p 21" \
  # Script Arguments
  "Checks for a stack-based buffer overflow in the ProFTPD server, version between 1.3.2rc3 and\n 1.3.3b. By sending a large number of TELNET_IAC escape sequence, the proftpd process\n miscalculates the buffer length, and a remote attacker will be able to corrupt the stack and \nexecute arbitrary code within the context of the proftpd process (CVE-2010-4221). Authentication is not required to exploit this vulnerability.\n \n https://nmap.org/nsedoc/scripts/ftp-vuln-cve2010-4221.html;\
  ;ftp-vuln-cve2010-4221;--script ftp-vuln-cve2010-4221 -p 21" \
  # Script Arguments
  "Attempts to exploit an authentication bypass vulnerability in Adobe Coldfusion servers to\n retrieve a valid administrator's session cookie (1).\n \n https://nmap.org/nsedoc/scripts/http-adobe-coldfusion-apsa1301.html;\
  ;http-adobe-coldfusion-apsa1301-1;-sV --script http-adobe-coldfusion-apsa1301" \
  # Script Arguments
  "Attempts to exploit an authentication bypass vulnerability in Adobe Coldfusion servers to\n retrieve a valid administrator's session cookie (2).\n \n https://nmap.org/nsedoc/scripts/http-adobe-coldfusion-apsa1301.html;\
  ;http-adobe-coldfusion-apsa1301-2;--script http-adobe-coldfusion-apsa1301 --script-args basepath=/cf/adminapi/ -p 80" \
  # Script Arguments
  "Determines if a ASP.NET application has debugging enabled using a HTTP DEBUG request (1).\n \n https://nmap.org/nsedoc/scripts/http-aspnet-debug.html;\
  ;http-aspnet-debug-1;--script http-aspnet-debug" \
  # Script Arguments
  "Determines if a ASP.NET application has debugging enabled using a HTTP DEBUG request (2).\n \n https://nmap.org/nsedoc/scripts/http-aspnet-debug.html;\
  ;http-aspnet-debug-2;--script http-aspnet-debug --script-args http-aspnet-debug.path=/path" \
  # Script Arguments
  "Attempts to enumerate users in Avaya IP Office systems 7.x (1).\n \n https://nmap.org/nsedoc/scripts/http-avaya-ipoffice-users.html;\
  ;http-avaya-ipoffice-users-1;-sV --script http-avaya-ipoffice-users" \
  # Script Arguments
  "Attempts to enumerate users in Avaya IP Office systems 7.x (2).\n \n https://nmap.org/nsedoc/scripts/http-avaya-ipoffice-users.html;\
  ;http-avaya-ipoffice-users-2;--script http-avaya-ipoffice-users -p 80" \
  # Script Arguments
  "Exploits a remote code execution vulnerability in Awstats Totals 1.0 up to 1.14 and possibly\n other products based on it (CVE: 2008-3922) (1).\n \n https://nmap.org/nsedoc/scripts/http-awstatstotals-exec.html;\
  ;http-awstatstotals-exec-1;-sV --script http-awstatstotals-exec.nse" \
  # Script Arguments
  "Exploits a remote code execution vulnerability in Awstats Totals 1.0 up to 1.14 and possibly\n other products based on it (CVE: 2008-3922) (2).\n \n https://nmap.org/nsedoc/scripts/http-awstatstotals-exec.html;\
  ;http-awstatstotals-exec-2;-sV --script http-awstatstotals-exec.nse --script-args 'http-awstatstotals-exec.cmd=\"uname -a\", http-awstatstotals-exec.uri=/awstats/index.php'" \
  # Script Arguments
  "Exploits a directory traversal vulnerability in Apache Axis2 version 1.4.1 by sending a specially\n crafted request to the parameter xsd (OSVDB-59001). By default it will try to\n retrieve the configuration file of the Axis2 service '/conf/axis2.xml' using the path '/axis2/services/'\n to return the username and password of the admin account (1).\n \n https://nmap.org/nsedoc/scripts/http-axis2-dir-traversal.html;\
  ;http-axis2-dir-traversal-1;--script http-axis2-dir-traversal -p 80" \
  # Script Arguments
  "Exploits a directory traversal vulnerability in Apache Axis2 version 1.4.1 by sending a specially\n crafted request to the parameter xsd (OSVDB-59001). By default it will try to\n retrieve the configuration file of the Axis2 service '/conf/axis2.xml' using the path '/axis2/services/'\n to return the username and password of the admin account (2).\n \n https://nmap.org/nsedoc/scripts/http-axis2-dir-traversal.html;\
  ;http-axis2-dir-traversal-2;--script http-axis2-dir-traversal --script-args 'http-axis2-dir-traversal.file=../../../../../../../etc/issue' -p 80,8080 " \
  # Script Arguments
  "Examines cookies set by HTTP services. Reports any session cookies set without the httponly flag.\n Reports any session cookies set over SSL without the secure flag.\n If http-enum.nse is also run, any interesting paths found by it will be checked in addition to the root.\n \n https://nmap.org/nsedoc/scripts/http-cookie-flags.html;\
  ;http-cookie-flags;--script http-cookie-flags -p 443" \
  # Script Arguments
  "Checks the cross-domain policy file (/crossdomain.xml) and the client-acces-policy file (/clientaccesspolicy.xml)\n in web applications and lists the trusted domains. Overly permissive\n settings enable Cross Site Request Forgery attacks and may allow attackers to access sensitive data.\n This script is useful to detect permissive configurations and possible domain names available for purchase to exploit the application.\n \n https://nmap.org/nsedoc/scripts/http-cross-domain-policy.html;\
  ;http-cross-domain-policy-1;--script http-cross-domain-policy" \
  # Script Arguments
  "Checks the cross-domain policy file (/crossdomain.xml) and the client-acces-policy file (/clientaccesspolicy.xml)\n in web applications and lists the trusted domains. Overly permissive\n settings enable Cross Site Request Forgery attacks and may allow attackers to access sensitive data.\n This script is useful to detect permissive configurations and possible domain names available for purchase to exploit the application.\n \n https://nmap.org/nsedoc/scripts/http-cross-domain-policy.html;\
  ;http-cross-domain-policy-2;--script http-cross-domain-policy --script-args http-cross-domain-policy.domain-lookup=true -p 80" \
  # Script Arguments
  "This script detects Cross Site Request Forgeries (CSRF) vulnerabilities.;\
  ;http-csrf;--script http-csrf.nse -p 80" \
  # Script Arguments
  "Detects a firmware backdoor on some D-Link routers by changing the User-Agent to a \"secret\" value.\n Using the \"secret\" User-Agent bypasses authentication and allows admin access to the router.\n The following router models are likely to be vulnerable: DIR-100, DIR-120, DI-624S, DI-524UP,\n DI-604S, DI-604UP, DI-604+, TM-G5240\n \n https://nmap.org/nsedoc/scripts/http-dlink-backdoor.html;\
  ;http-dlink-backdoor;-sV --script http-dlink-backdoor" \
  # Script Arguments
  "It looks for places where attacker-controlled information in the DOM may be used\n to affect JavaScript execution in certain ways.\n The attack is explained here: http://www.webappsec.org/projects/articles/071105.shtml\n \n https://nmap.org/nsedoc/scripts/http-dombased-xss.html;\
  ;http-dombased-xss;--script http-dombased-xss.nse -p 80" \
  # Script Arguments
  "Enumerates directories used by popular web applications and servers.\n \n https://nmap.org/nsedoc/scripts/http-enum.html;\
  ;http-enum;-sV --script=http-enum -p 80,443,8080" \
  # Script Arguments
  "Exploits insecure file upload forms in web applications using various techniques\n like changing the Content-type header or creating valid image files containing the payload in the comment.\n \n https://nmap.org/nsedoc/scripts/http-fileupload-exploiter.html;\
  ;http-fileupload-exploiter;--script http-fileupload-exploiter.nse -p 80" \
  # Script Arguments
  "Checks whether target machines are vulnerable to anonymous Frontpage login.\n \n https://nmap.org/nsedoc/scripts/http-frontpage-login.html;\
  ;http-frontpage-login;--script=http-frontpage-login -p 80" \
  # Script Arguments
  "Checks for a Git repository found in a website's document root /.git/<something>)\n and retrieves as much repo information as possible, including language/framework, remotes, last commit message,\n and repository description.\n \n https://nmap.org/nsedoc/scripts/http-git.html;\
  ;http-git;-sV -sC" \
  # Script Arguments
  "Detects Huawei modems models HG530x, HG520x, HG510x (and possibly others...)\n vulnerable to a remote credential and information disclosure vulnerability. It also extracts the PPPoE credentials\n and other interesting configuration values.\n \n https://nmap.org/nsedoc/scripts/http-huawei-hg5xx-vuln.html;\
  ;http-huawei-hg5xx-vuln-1;--script http-huawei-hg5xx-vuln -p 80" \
  # Script Arguments
  "Detects Huawei modems models HG530x, HG520x, HG510x (and possibly others...)\n vulnerable to a remote credential and information disclosure vulnerability. It also extracts the PPPoE credentials\n and other interesting configuration values.\n \n https://nmap.org/nsedoc/scripts/http-huawei-hg5xx-vuln.html;\
  ;http-huawei-hg5xx-vuln-2;-sV http-huawei-hg5xx-vuln" \
  # Script Arguments
  "Checks for a vulnerability in IIS 5.1/6.0 that allows arbitrary users to access secured\n WebDAV folders by searching for a password-protected folder and attempting to access it. This vulnerability was patched\n in Microsoft Security Bulletin MS09-020, https://nmap.org/r/ms09-020.\n \n https://nmap.org/nsedoc/scripts/http-iis-webdav-vuln.html;\
  ;http-iis-webdav-vuln;--script http-iis-webdav-vuln -p80,8080" \
  # Script Arguments
  "Determines if the web server leaks its internal IP address when sending an HTTP/1.0\n request without a Host header.\n \n https://nmap.org/nsedoc/scripts/http-internal-ip-disclosure.html;\
  ;http-internal-ip-disclosure-1;--script http-internal-ip-disclosure" \
  # Script Arguments
  "Attempts to discover JSONP endpoints in web servers. JSONP endpoints can be used to bypass\n Same-origin Policy restrictions in web browsers. The script searches for callback functions in the response\n to detect JSONP endpoints. It also tries to determine callback function through URL(callback function may be fully or partially\n controllable from URL) and also tries to bruteforce the most common callback variables through the URL.\n \n https://nmap.org/nsedoc/scripts/http-jsonp-detection.html;\
  ;http-jsonp-detection;--script http-jsonp-detection -p" \
  # Script Arguments
  "Exploits a null-byte poisoning vulnerability in Litespeed Web Servers 4.0.x before 4.0.15\n to retrieve the target script's source code by sending a HTTP request with a null byte followed by a .txt file extension (CVE-2010-2333).\n \n https://nmap.org/nsedoc/scripts/http-litespeed-sourcecode-download.html;\
  ;http-litespeed-sourcecode-download-1;--script http-litespeed-sourcecode-download -p 8088" \
  # Script Arguments
  "Exploits a null-byte poisoning vulnerability in Litespeed Web Servers 4.0.x before 4.0.15\n to retrieve the target script's source code by sending a HTTP request with a null byte followed by a .txt file extension (CVE-2010-2333).\n \n https://nmap.org/nsedoc/scripts/http-litespeed-sourcecode-download.html;\
  ;http-litespeed-sourcecode-download-2;--script http-litespeed-sourcecode-download --script-args http-litespeed-sourcecode-download.uri=/phpinfo.php -p 80" \
  # Script Arguments
  "Exploits a directory traversal vulnerability existing in Majordomo2 to retrieve remote files.\n (CVE-2011-0049).\n \n https://nmap.org/nsedoc/scripts/http-majordomo2-dir-traversal.html;\
  ;http-majordomo2-dir-traversal;--script http-majordomo2-dir-traversal -p 80" \
  # Script Arguments
  "Attempts to bypass password protected resources (HTTP 401 status) by performing HTTP verb tampering.\n If an array of paths to check is not set, it will crawl the web server and perform the check against any password protected\n resource that it finds.\n \n https://nmap.org/nsedoc/scripts/http-method-tamper.html;\
  ;http-method-tamper-1;-sV --script http-method-tamper" \
  # Script Arguments
  "Attempts to bypass password protected resources (HTTP 401 status) by performing HTTP verb tampering.\n If an array of paths to check is not set, it will crawl the web server and perform the check against any password protected\n resource that it finds.\n \n https://nmap.org/nsedoc/scripts/http-method-tamper.html;\
  ;http-method-tamper-2;--script http-method-tamper --script-args 'http-method-tamper.paths={/protected/db.php,/protected/index.php}' -p 80" \
  # Script Arguments
  "Checks if a web server is vulnerable to directory traversal by attempting to retrieve /etc/passwd\n or \boot.ini.\n \n ;\
  ;http-passwd;--script http-passwd --script-args http-passwd.root=/test/" \
  # Script Arguments
  "Exploits a directory traversal vulnerability in phpMyAdmin 2.6.4-pl1 (and possibly other versions)\n to retrieve remote files on the web server.\n \n https://nmap.org/nsedoc/scripts/http-phpmyadmin-dir-traversal.html;\
  ;http-phpmyadmin-dir-traversal-1;--script http-phpmyadmin-dir-traversal -p 80" \
  # Script Arguments
  "Exploits a directory traversal vulnerability in phpMyAdmin 2.6.4-pl1 (and possibly other versions)\n to retrieve remote files on the web server.\n \n https://nmap.org/nsedoc/scripts/http-phpmyadmin-dir-traversal.html;\
  ;http-phpmyadmin-dir-traversal-2;--script http-phpmyadmin-dir-traversal --script-args=\"dir='/pma/',file='../../../../../../../../etc/passwd',outfile='passwd.txt'\" -p 80" \
  # Script Arguments
  "Crawls a web server and attempts to find PHP files vulnerable to reflected cross site scripting\n via the variable '\$_SERVER[\"PHP_SELF\"]'.\n \n https://nmap.org/nsedoc/scripts/http-phpself-xss.html;\
  ;http-phpself-xss-1;-sV --script http-self-xss" \
  # Script Arguments
  "Crawls a web server and attempts to find PHP files vulnerable to reflected cross site scripting\n via the variable '\$_SERVER[\"PHP_SELF\"]'.\n \n https://nmap.org/nsedoc/scripts/http-phpself-xss.html;\
  ;http-phpself-xss-2;--script=http-phpself-xss -p 80" \
  # Script Arguments
  "Attempts to exploit the \"shellshock\" vulnerability (CVE-2014-6271 and CVE-2014-7169)\n in web applications.\n \n https://nmap.org/nsedoc/scripts/http-shellshock.html;\
  ;http-shellshock-1;-sV -p- --script http-shellshock" \
  # Script Arguments
  "Attempts to exploit the \"shellshock\" vulnerability (CVE-2014-6271 and CVE-2014-7169)\n in web applications.\n \n https://nmap.org/nsedoc/scripts/http-shellshock.html;\
  ;http-shellshock-2;-sV -p- --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls" \
  # Script Arguments
  "Tests a web server for vulnerability to the Slowloris DoS attack without actually launching\n a DoS attack.\n \n https://nmap.org/nsedoc/scripts/http-slowloris-check.html;\
  ;http-slowloris-check;--script http-slowloris-check -p 80,443,8080" \
  # Script Arguments
  "Spiders an HTTP server looking for URLs containing queries vulnerable to an SQL injection attack. It also\n extracts forms from found websites and tries to identify fields that are vulnerable.\n \n https://nmap.org/nsedoc/scripts/http-sql-injection.html;\
  ;http-sql-injection;-sV --script=http-sql-injection -p 80" \
  # Script Arguments
  "Unfiltered '>' (greater than sign). An indication of potential XSS vulnerability.\n \n https://nmap.org/nsedoc/scripts/http-stored-xss.html;\
  ;http-stored-xss;--script http-stored-xss.nse -p 80" \
  # Script Arguments
  "Exploits a directory traversal vulnerability existing in several TP-Link wireless routers.\n Attackers may exploit this vulnerability to read any of the configuration and password files remotely\n and without authentication.\n \n https://nmap.org/nsedoc/scripts/http-tplink-dir-traversal.html;\
  ;http-tplink-dir-traversal-1;--script http-tplink-dir-traversal.nse -p 80" \
  # Script Arguments
  "Exploits a directory traversal vulnerability existing in several TP-Link wireless routers.\n Attackers may exploit this vulnerability to read any of the configuration and password files remotely\n and without authentication.\n \n https://nmap.org/nsedoc/scripts/http-tplink-dir-traversal.html;\
  ;http-tplink-dir-traversal-2;-Pn -n --script http-tplink-dir-traversal.nse -p 80" \
  # Script Arguments
  "Exploits a directory traversal vulnerability existing in several TP-Link wireless routers.\n Attackers may exploit this vulnerability to read any of the configuration and password files remotely\n and without authentication.\n \n https://nmap.org/nsedoc/scripts/http-tplink-dir-traversal.html;\
  ;http-tplink-dir-traversal-3;--script http-tplink-dir-traversal.nse --script-args rfile=/etc/topology.conf -d -n -Pn -p 80" \
  # Script Arguments
  "Sends an HTTP TRACE request and shows if the method TRACE is enabled.\n If debug is enabled, it returns the header fields that were modified in the response.\n \n https://nmap.org/nsedoc/scripts/http-trace.html;\
  ;http-trace;--script http-trace -d" \
  # Script Arguments
  "Checks for a path-traversal vulnerability in VMWare ESX, ESXi, and Server (CVE-2009-3733).\n \n https://nmap.org/nsedoc/scripts/http-vmware-path-vuln.html;\
  ;http-vmware-path-vuln;--script http-vmware-path-vuln -p80,443,8222,8333" \
  # Script Arguments
  "Exploits a file disclosure vulnerability in Webmin (CVE-2006-3392)\n \n https://nmap.org/nsedoc/scripts/http-vuln-cve2006-3392.html;\
  ;http-vuln-cve2006-3392-1;-sV --script http-vuln-cve2006-3392" \
  # Script Arguments
  "Exploits a file disclosure vulnerability in Webmin (CVE-2006-3392)\n \n https://nmap.org/nsedoc/scripts/http-vuln-cve2006-3392.html;\
  ;http-vuln-cve2006-3392-2;--script http-vuln-cve2006-3392 --script-args http-vuln-cve2006-3392.file=/etc/shadow -p 80" \
  # Script Arguments
  "Exploits cve-2009-3960 also known as Adobe XML External Entity Injection.\n \n https://nmap.org/nsedoc/scripts/http-vuln-cve2009-3960.html;\
  ;http-vuln-cve2009-3960;--script=http-vuln-cve2009-3960 --script-args http-http-vuln-cve2009-3960.root=\"/root/\"" \
  # Script Arguments
  "Tests whether a JBoss target is vulnerable to jmx console authentication bypass\n (CVE-2010-0738).\n \n https://nmap.org/nsedoc/scripts/http-vuln-cve2010-0738.html;\
  ;http-vuln-cve2010-0738;--script=http-vuln-cve2010-0738 --script-args 'http-vuln-cve2010-0738.paths={/path1/,/path2/}'" \
  # Script Arguments
  "Executes a directory traversal attack against a ColdFusion server and tries to\n grab the password hash for the administrator user. It then uses the salt value (hidden in the web page)\n to create the SHA1 HMAC hash that the web server needs for authentication as admin.\n You can pass this value to the ColdFusion server as the admin without cracking the password hash.\n \n https://nmap.org/nsedoc/scripts/http-vuln-cve2010-2861.html;\
  ;http-vuln-cve2010-2861;--script http-vuln-cve2010-2861" \
  # Script Arguments
  "Detects a denial of service vulnerability in the way the Apache web server handles\n requests for multiple overlapping/simple ranges of a page.\n \n ;\
  ;http-vuln-cve2011-3192;--script http-vuln-cve2011-3192.nse [--script-args http-vuln-cve2011-3192.hostname=nmap.scanme.org] -pT:80,443" \
  # Script Arguments
  "Tests for the CVE-2011-3368 (Reverse Proxy Bypass) vulnerability in Apache HTTP\n server's reverse proxy mode.\n \n https://nmap.org/nsedoc/scripts/http-vuln-cve2011-3368.html;\
  ;http-vuln-cve2011-3368;--script http-vuln-cve2011-3368" \
  # Script Arguments
  "Detects PHP-CGI installations that are vulnerable to CVE-2012-1823, This critical\n vulnerability allows attackers to retrieve source code and execute code remotely.\n \n https://nmap.org/nsedoc/scripts/http-vuln-cve2012-1823.html;\
  ;http-vuln-cve2012-1823-1;-sV --script http-vuln-cve2012-1823" \
   # Script Arguments
  "Detects PHP-CGI installations that are vulnerable to CVE-2012-1823, This critical\n vulnerability allows attackers to retrieve source code and execute code remotely.\n \n https://nmap.org/nsedoc/scripts/http-vuln-cve2012-1823.html;\
  ;http-vuln-cve2012-1823-2;--script http-vuln-cve2012-1823 --script-args http-vuln-cve2012-1823.uri=/test.php -p 80" \
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
