#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_vuln()
#
# Description:
#   NSE 'vuln' category module.
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
  description="NSE 'vuln' category module"

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

      URL: https://nmap.org/nsedoc/categories/vuln.html

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
  "Attempts to discover hosts in the local network using the DNS Service\n \
  Discovery protocol and sends a NULL UDP packet to each host to test if it is\n \
  vulnerable to the Avahi NULL UDP packet denial of service (CVE-2011-1002).\n \
  \n https://nmap.org/nsedoc/scripts/broadcast-avahi-dos.html;\
  ;broadcast-avahi-dos;--script=broadcast-avahi-dos" \
  #
  "Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution\n \
  (1).\n \
  \n https://nmap.org/nsedoc/scripts/clamav-exec.html;\
  ;clamav-exec-1;-sV --script clamav-exec" \
  #
  "Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution\n \
  (2).\n \
  \n https://nmap.org/nsedoc/scripts/clamav-exec.html;\
  ;clamav-exec-2;--script clamav-exec --script-args cmd='scan',scandb='files.txt'" \
  #
  "Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution\n \
  (3).\n \
  \n https://nmap.org/nsedoc/scripts/clamav-exec.html;\
  ;clamav-exec-3;--script clamav-exec --script-args cmd='shutdown'" \
  # Script Arguments
  "Attempts to perform a dynamic DNS update without authentication.\n \
  \n https://nmap.org/nsedoc/scripts/dns-update.html;\
  ;dns-update;-sU --script=dns-update --script-args=dns-update.hostname=foo.example.com,dns-update.ip=192.0.2.1 -p 53" \
  # Script Arguments
  "Detects a vulnerability in netfilter and other firewalls that use helpers to\n \
  dynamically open ports for protocols such as ftp and sip (1).\n \
  \n https://nmap.org/nsedoc/scripts/firewall-bypass.html;\
  ;firewall-bypass-1;--script firewall-bypass" \
  # Script Arguments
  "Detects a vulnerability in netfilter and other firewalls that use helpers to\n \
  dynamically\n open ports for protocols such as ftp and sip (2).\n \
  \n https://nmap.org/nsedoc/scripts/firewall-bypass.html;\
  ;firewall-bypass-2;--script firewall-bypass --script-args firewall-bypass.helper=\"ftp\", firewall-bypass.targetport=22" \
  #
  "Checks if an FTPd is prone to CVE-2010-1938 (OPIE off-by-one stack overflow),\n \
  a vulnerability discovered by Maksymilian Arciemowicz and Adam \"pi3\"\n \
  Zabrocki. See the advisory at https://nmap.org/r/fbsd-sa-opie. Be advised\n \
  that, if launched against a vulnerable host, this script will crash the\n \
  FTPd.\n \
  \n https://nmap.org/nsedoc/scripts/ftp-libopie.html;\
  ;ftp-libopie;-sV --script=ftp-libopie" \
  # Script Arguments
  "Tests for the presence of the ProFTPD 1.3.3c backdoor reported as OSVDB-ID\n \
  69562. This script attempts to exploit the backdoor using the innocuous id\n \
  command by default,\n but that can be changed with the\n \
  ftp-proftpd-backdoor.cmd script argument.\n \
  \n https://nmap.org/nsedoc/scripts/ftp-proftpd-backdoor.html;\
  ;ftp-proftpd-backdoor;--script ftp-proftpd-backdoor -p 21" \
  # Script Arguments
  "Tests for the presence of the vsFTPd 2.3.4 backdoor reported on 2011-07-04\n \
  (CVE-2011-2523).\n This script attempts to exploit the backdoor using the\n \
  innocuous id command by default,\n but that can be changed with the\n \
  exploit.cmd or ftp-vsftpd-backdoor.cmd script arguments.\n \
  \n https://nmap.org/nsedoc/scripts/ftp-vsftpd-backdoor.html;\
  ;ftp-vsftpd-backdoor;--script ftp-vsftpd-backdoor -p 21" \
  # Script Arguments
  "Checks for a stack-based buffer overflow in the ProFTPD server, version\n \
  between 1.3.2rc3 and 1.3.3b. By sending a large number of TELNET_IAC escape\n \
  sequence, the proftpd process miscalculates the buffer length, and a remote\n \
  attacker will be able to corrupt the stack and execute arbitrary code within\n \
  the context of the proftpd process (CVE-2010-4221). Authentication is not\n \
  required to exploit this vulnerability.\n \
  \n https://nmap.org/nsedoc/scripts/ftp-vuln-cve2010-4221.html;\
  ;ftp-vuln-cve2010-4221;--script ftp-vuln-cve2010-4221 -p 21" \
  # Script Arguments
  "Determines if a ASP.NET application has debugging enabled using a HTTP DEBUG\n \
  request (1).\n \
  \n https://nmap.org/nsedoc/scripts/http-aspnet-debug.html;\
  ;http-aspnet-debug-1;--script http-aspnet-debug" \
  # Script Arguments
  "Determines if a ASP.NET application has debugging enabled using a HTTP DEBUG\n \
  request (2).\n \
  \n https://nmap.org/nsedoc/scripts/http-aspnet-debug.html;\
  ;http-aspnet-debug-2;--script http-aspnet-debug --script-args http-aspnet-debug.path=/path" \
  # Script Arguments
  "Attempts to enumerate users in Avaya IP Office systems 7.x (1).\n \
  \n https://nmap.org/nsedoc/scripts/http-avaya-ipoffice-users.html;\
  ;http-avaya-ipoffice-users-1;-sV --script http-avaya-ipoffice-users" \
  # Script Arguments
  "Attempts to enumerate users in Avaya IP Office systems 7.x (2).\n \
  \n https://nmap.org/nsedoc/scripts/http-avaya-ipoffice-users.html;\
  ;http-avaya-ipoffice-users-2;--script http-avaya-ipoffice-users -p 80" \
  # Script Arguments
  "Exploits a remote code execution vulnerability in Awstats Totals 1.0 up to\n \
  1.14 and possibly other products based on it (CVE: 2008-3922) (1).\n \
  \n https://nmap.org/nsedoc/scripts/http-awstatstotals-exec.html;\
  ;http-awstatstotals-exec-1;-sV --script http-awstatstotals-exec.nse" \
  # Script Arguments
  "Exploits a remote code execution vulnerability in Awstats Totals 1.0 up to\n \
  1.14 and possibly other products based on it (CVE: 2008-3922) (2).\n \
  \n https://nmap.org/nsedoc/scripts/http-awstatstotals-exec.html;\
  ;http-awstatstotals-exec-2;-sV --script http-awstatstotals-exec.nse --script-args 'http-awstatstotals-exec.cmd=\"uname -a\", http-awstatstotals-exec.uri=/awstats/index.php'" \
  # Script Arguments
  "Examines cookies set by HTTP services. Reports any session cookies set\n \
  without the httponly flag. Reports any session cookies set over SSL without\n \
  the secure flag. If http-enum.nse is also run, any interesting paths found\n \
  by it will be checked in addition to the root.\n \
  \n https://nmap.org/nsedoc/scripts/http-cookie-flags.html;\
  ;http-cookie-flags;--script http-cookie-flags -p 443" \
  # Script Arguments
  "Checks the cross-domain policy file (/crossdomain.xml) and the\n \
  client-acces-policy file (/clientaccesspolicy.xml)\n in web applications and\n \
  lists the trusted domains. Overly permissive\n settings enable Cross Site\n \
  Request Forgery attacks and may allow attackers to access sensitive data.\n \
  This script is useful to detect permissive configurations and possible domain\n \
  names available for purchase to exploit the application.\n \
  \n https://nmap.org/nsedoc/scripts/http-cross-domain-policy.html;\
  ;http-cross-domain-policy-1;--script http-cross-domain-policy" \
  # Script Arguments
  "Checks the cross-domain policy file (/crossdomain.xml) and the\n \
  client-acces-policy file (/clientaccesspolicy.xml)\n in web applications and\n \
  lists the trusted domains. Overly permissive\n settings enable Cross Site\n \
  Request Forgery attacks and may allow attackers to access sensitive data.\n \
  This script is useful to detect permissive configurations and possible domain\n \
  names available for purchase to exploit the application.\n \
  \n https://nmap.org/nsedoc/scripts/http-cross-domain-policy.html;\
  ;http-cross-domain-policy-2;--script http-cross-domain-policy --script-args http-cross-domain-policy.domain-lookup=true -p 80" \
  # Script Arguments
  "This script detects Cross Site Request Forgeries (CSRF) vulnerabilities.\n \
  \n \https://nmap.org/nsedoc/scripts/http-csrf.html;\
  ;http-csrf;--script http-csrf.nse -p 80" \
  # Script Arguments
  "Detects a firmware backdoor on some D-Link routers by changing the User-Agent\n \
  to a \"secret\" value. Using the \"secret\" User-Agent bypasses\n \
  authentication and allows admin access to the router. The following router\n \
  models are likely to be vulnerable: DIR-100, DIR-120, DI-624S, DI-524UP,\n \
  DI-604S, DI-604UP, DI-604+, TM-G5240\n \
  \n https://nmap.org/nsedoc/scripts/http-dlink-backdoor.html;\
  ;http-dlink-backdoor;-sV --script http-dlink-backdoor" \
  # Script Arguments
  "It looks for places where attacker-controlled information in the DOM may be\n \
  used to affect JavaScript execution in certain ways. The attack is explained\n \
  here: http://www.webappsec.org/projects/articles/071105.shtml\n \
  \n https://nmap.org/nsedoc/scripts/http-dombased-xss.html;\
  ;http-dombased-xss;--script http-dombased-xss.nse -p 80" \
  # Script Arguments
  "Enumerates directories used by popular web applications and servers.\n \
  \n https://nmap.org/nsedoc/scripts/http-enum.html;\
  ;http-enum;-sV --script=http-enum -p 80,443,8080" \
  # Script Arguments
  "Exploits insecure file upload forms in web applications using various\n \
  techniques\n like changing the Content-type header or creating valid image\n \
  files containing the payload in the comment.\n \
  \n https://nmap.org/nsedoc/scripts/http-fileupload-exploiter.html;\
  ;http-fileupload-exploiter;--script http-fileupload-exploiter.nse -p 80" \
  # Script Arguments
  "Checks whether target machines are vulnerable to anonymous Frontpage login.\n \
  \n https://nmap.org/nsedoc/scripts/http-frontpage-login.html;\
  ;http-frontpage-login;--script=http-frontpage-login -p 80" \
  # Script Arguments
  "Checks for a Git repository found in a website's document root\n \
  /.git/<something>) and retrieves as much repo information as possible,\n \
  including language/framework, remotes, last commit message,\n and repository\n \
  description.\n \
  \n https://nmap.org/nsedoc/scripts/http-git.html;\
  ;http-git;-sV -sC" \
  # Script Arguments
  "Checks for a vulnerability in IIS 5.1/6.0 that allows arbitrary users to\n \
  access secured WebDAV folders by searching for a password-protected folder\n \
  and attempting to access it. This vulnerability was patched in Microsoft\n \
  Security Bulletin MS09-020, https://nmap.org/r/ms09-020.\n \
  \n https://nmap.org/nsedoc/scripts/http-iis-webdav-vuln.html;\
  ;http-iis-webdav-vuln;--script http-iis-webdav-vuln -p80,8080" \
  # Script Arguments
  "Determines if the web server leaks its internal IP address when sending an\n \
  HTTP/1.0 request without a Host header.\n \
  \n https://nmap.org/nsedoc/scripts/http-internal-ip-disclosure.html;\
  ;http-internal-ip-disclosure-1;--script http-internal-ip-disclosure" \
  # Script Arguments
  "Attempts to discover JSONP endpoints in web servers. JSONP endpoints can be\n \
  used to bypass Same-origin Policy restrictions in web browsers. The script\n \
  searches for callback functions in the response to detect JSONP endpoints. It\n \
  also tries to determine callback function through URL(callback function may be\n \
  fully or partially controllable from URL) and also tries to bruteforce the\n \
  most common callback variables through the URL.\n \
  \n https://nmap.org/nsedoc/scripts/http-jsonp-detection.html;\
  ;http-jsonp-detection;--script http-jsonp-detection -p" \
  # Script Arguments
  "Exploits a null-byte poisoning vulnerability in Litespeed Web Servers 4.0.x\n \
  before 4.0.15 to retrieve the target script's source code by sending a HTTP\n \
  request with a null byte followed by a .txt file extension (CVE-2010-2333).\n \
  \n https://nmap.org/nsedoc/scripts/http-litespeed-sourcecode-download.html;\
  ;http-litespeed-sourcecode-download-1;--script http-litespeed-sourcecode-download -p 8088" \
  # Script Arguments
  "Exploits a null-byte poisoning vulnerability in Litespeed Web Servers 4.0.x\n \
  before 4.0.15 to retrieve the target script's source code by sending a HTTP\n \
  request with a null byte followed by a .txt file extension (CVE-2010-2333).\n \
  \n https://nmap.org/nsedoc/scripts/http-litespeed-sourcecode-download.html;\
  ;http-litespeed-sourcecode-download-2;--script http-litespeed-sourcecode-download --script-args http-litespeed-sourcecode-download.uri=/phpinfo.php -p 80" \
  # Script Arguments
  "Attempts to bypass password protected resources (HTTP 401 status) by\n \
  performing HTTP verb tampering. If an array of paths to check is not set, it\n \
  will crawl the web server and perform the check against any password\n \
  protected\n resource that it finds.\n \
  \n https://nmap.org/nsedoc/scripts/http-method-tamper.html;\
  ;http-method-tamper-1;-sV --script http-method-tamper" \
  # Script Arguments
  "Attempts to bypass password protected resources (HTTP 401 status) by\n \
  performing HTTP verb tampering. If an array of paths to check is not set, it\n \
  will crawl the web server and perform the check against any password\n \
  protected\n resource that it finds.\n \
  \n https://nmap.org/nsedoc/scripts/http-method-tamper.html;\
  ;http-method-tamper-2;--script http-method-tamper --script-args 'http-method-tamper.paths={/protected/db.php,/protected/index.php}' -p 80" \
  # Script Arguments
  "Checks if a web server is vulnerable to directory traversal by attempting to\n \
  retrieve /etc/passwd or \boot.ini.\n \
  https://nmap.org/nsedoc/scripts/http-passwd.html;\
  ;http-passwd;--script http-passwd --script-args http-passwd.root=/test/" \
  # Script Arguments
  "Exploits a directory traversal vulnerability in phpMyAdmin 2.6.4-pl1 (and\n \
  possibly other versions) to retrieve remote files on the web server.\n \
  \n https://nmap.org/nsedoc/scripts/http-phpmyadmin-dir-traversal.html;\
  ;http-phpmyadmin-dir-traversal-1;--script http-phpmyadmin-dir-traversal -p 80" \
  # Script Arguments
  "Exploits a directory traversal vulnerability in phpMyAdmin 2.6.4-pl1 (and\n \
  possibly other versions) to retrieve remote files on the web server.\n \
  \n https://nmap.org/nsedoc/scripts/http-phpmyadmin-dir-traversal.html;\
  ;http-phpmyadmin-dir-traversal-2;--script http-phpmyadmin-dir-traversal --script-args=\"dir='/pma/',file='../../../../../../../../etc/passwd',outfile='passwd.txt'\" -p 80" \
  # Script Arguments
  "Crawls a web server and attempts to find PHP files vulnerable to reflected\n \
  cross site scripting via the variable '\$_SERVER[\"PHP_SELF\"]'.\n \
  \n https://nmap.org/nsedoc/scripts/http-phpself-xss.html;\
  ;http-phpself-xss-1;-sV --script http-self-xss" \
  # Script Arguments
  "Crawls a web server and attempts to find PHP files vulnerable to reflected\n \
  cross site scripting via the variable '\$_SERVER[\"PHP_SELF\"]'.\n \
  \n https://nmap.org/nsedoc/scripts/http-phpself-xss.html;\
  ;http-phpself-xss-2;--script=http-phpself-xss -p 80" \
  # Script Arguments
  "Attempts to exploit the \"shellshock\" vulnerability (CVE-2014-6271 and\n \
  CVE-2014-7169) in web applications.\n \
  \n https://nmap.org/nsedoc/scripts/http-shellshock.html;\
  ;http-shellshock-1;-sV -p- --script http-shellshock" \
  # Script Arguments
  "Attempts to exploit the \"shellshock\" vulnerability (CVE-2014-6271 and\n \
  CVE-2014-7169) in web applications.\n \
  \n https://nmap.org/nsedoc/scripts/http-shellshock.html;\
  ;http-shellshock-2;-sV -p- --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls" \
  # Script Arguments
  "Tests a web server for vulnerability to the Slowloris DoS attack without\n \
  actually launching a DoS attack.\n \
  \n https://nmap.org/nsedoc/scripts/http-slowloris-check.html;\
  ;http-slowloris-check;--script http-slowloris-check -p 80,443,8080" \
  # Script Arguments
  "Spiders an HTTP server looking for URLs containing queries vulnerable to an\n \
  SQL injection attack. It also extracts forms from found websites and tries\n \
  to identify fields that are vulnerable.\n \
  \n https://nmap.org/nsedoc/scripts/http-sql-injection.html;\
  ;http-sql-injection;-sV --script=http-sql-injection -p 80" \
  # Script Arguments
  "Unfiltered '>' (greater than sign). An indication of potential XSS\n \
  vulnerability.\n \
  \n https://nmap.org/nsedoc/scripts/http-stored-xss.html;\
  ;http-stored-xss;--script http-stored-xss.nse -p 80" \
  # Script Arguments
  "Exploits a directory traversal vulnerability existing in several TP-Link\n \
  wireless routers. Attackers may exploit this vulnerability to read any of\n \
  the configuration and password files remotely and without authentication.\n \
  \n https://nmap.org/nsedoc/scripts/http-tplink-dir-traversal.html;\
  ;http-tplink-dir-traversal-1;--script http-tplink-dir-traversal.nse -p 80" \
  # Script Arguments
  "Exploits a directory traversal vulnerability existing in several TP-Link\n \
  wireless routers. Attackers may exploit this vulnerability to read any of\n \
  the configuration and password files remotely and without authentication.\n \
  \n https://nmap.org/nsedoc/scripts/http-tplink-dir-traversal.html;\
  ;http-tplink-dir-traversal-2;-Pn -n --script http-tplink-dir-traversal.nse -p 80" \
  # Script Arguments
  "Exploits a directory traversal vulnerability existing in several TP-Link\n \
  wireless routers. Attackers may exploit this vulnerability to read any of\n \
  the configuration and password files remotely and without authentication.\n \
  \n https://nmap.org/nsedoc/scripts/http-tplink-dir-traversal.html;\
  ;http-tplink-dir-traversal-3;--script http-tplink-dir-traversal.nse --script-args rfile=/etc/topology.conf -d -n -Pn -p 80" \
  # Script Arguments
  "Sends an HTTP TRACE request and shows if the method TRACE is enabled. If\n \
  debug is enabled, it returns the header fields that were modified in the\n \
  response.\n \
  \n https://nmap.org/nsedoc/scripts/http-trace.html;\
  ;http-trace;--script http-trace -d" \
  # Script Arguments
  "Checks for a path-traversal vulnerability in VMWare ESX, ESXi, and Server \n \
  (CVE-2009-3733).\n \
  \n https://nmap.org/nsedoc/scripts/http-vmware-path-vuln.html;\
  ;http-vmware-path-vuln;--script http-vmware-path-vuln -p80,443,8222,8333" \
  # Script Arguments
  "Exploits a file disclosure vulnerability in Webmin (CVE-2006-3392).\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2006-3392.html;\
  ;http-vuln-cve2006-3392-1;-sV --script http-vuln-cve2006-3392" \
  # Script Arguments
  "Exploits a file disclosure vulnerability in Webmin (CVE-2006-3392).\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2006-3392.html;\
  ;http-vuln-cve2006-3392-2;--script http-vuln-cve2006-3392 --script-args http-vuln-cve2006-3392.file=/etc/shadow -p 80" \
  # Script Arguments
  "Exploits cve-2009-3960 also known as Adobe XML External Entity Injection.\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2009-3960.html;\
  ;http-vuln-cve2009-3960;--script=http-vuln-cve2009-3960 --script-args http-http-vuln-cve2009-3960.root=\"/root/\"" \
  # Script Arguments
  "Tests whether a JBoss target is vulnerable to jmx console authentication\n \
  bypass\n (CVE-2010-0738).\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2010-0738.html;\
  ;http-vuln-cve2010-0738;--script=http-vuln-cve2010-0738 --script-args 'http-vuln-cve2010-0738.paths={/path1/,/path2/}'" \
  # Script Arguments
  "Detects a denial of service vulnerability in the way the Apache web server\n \
  handles requests for multiple overlapping/simple ranges of a page.\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2011-3192.html;\
  ;http-vuln-cve2011-3192;--script http-vuln-cve2011-3192.nse [--script-args http-vuln-cve2011-3192.hostname=nmap.scanme.org] -p T:80,443" \
  # Script Arguments
  "Tests for the CVE-2011-3368 (Reverse Proxy Bypass) vulnerability in Apache\n \
  HTTP server's reverse proxy mode.\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2011-3368.html;\
  ;http-vuln-cve2011-3368;--script http-vuln-cve2011-3368" \
  # Script Arguments
  "Detects PHP-CGI installations that are vulnerable to CVE-2012-1823, This\n \
  critical vulnerability allows attackers to retrieve source code and execute\n \
  code remotely.\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2012-1823.html;\
  ;http-vuln-cve2012-1823-1;-sV --script http-vuln-cve2012-1823" \
   # Script Arguments
  "Detects PHP-CGI installations that are vulnerable to CVE-2012-1823, This\n \
  critical vulnerability allows attackers to retrieve source code and execute\n \
  code remotely.\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2012-1823.html;\
  ;http-vuln-cve2012-1823-2;--script http-vuln-cve2012-1823 --script-args http-vuln-cve2012-1823.uri=/test.php -p 80" \
  #
  "Detects Ruby on Rails servers vulnerable to object injection, remote\n \
  command executions and denial of service attacks. (CVE-2013-0156)\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2013-0156.html;\
  ;http-vuln-cve2013-0156-1;-sV --script http-vuln-cve2013-0156" \
  #
  "Detects Ruby on Rails servers vulnerable to object injection, remote\n \
  command executions and denial of service attacks. (CVE-2013-0156)\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2013-0156.html;\
  ;http-vuln-cve2013-0156-2;-sV --script http-vuln-cve2013-0156 --script-args
  uri=\"/test/\"" \
  #
  "An 0 day was released on the 6th December 2013 by rubina119, and was\n \
  patched in Zimbra 7.2.6\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2013-7091.html;\
  ;http-vuln-cve2013-7091-1;-sV --script http-vuln-cve2013-7091" \
  #
  "An 0 day was released on the 6th December 2013 by rubina119, and was\n \
  patched in Zimbra 7.2.6.\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2013-7091.html;\
  ;http-vuln-cve2013-7091-2;--script http-vuln-cve2013-7091 --script-args http-vuln-cve2013-7091=/ZimBra -p 80" \
  #
  "Exploits CVE-2014-3704 also known as 'Drupageddon' in Drupal. Versions\n \
  <7.32 of Drupal core are known to be affected.\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2014-3704.html;\n \
  ;http-vuln-cve2014-3704-1;--script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.cmd=\"uname -a\",http-vuln-cve2014-3704.uri=\"/drupal\"" \
  #
  "Exploits CVE-2014-3704 also known as 'Drupageddon' in Drupal. Versions\n \
  <7.32 of Drupal core are known to be affected.\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2014-3704.html;\n \
  ;http-vuln-cve2014-3704-2;--script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.uri=\"/drupal\",http-vuln-cve2014-3704.cleanup=false" \
  #
  "This script attempts to detect a vulnerability, CVE-2015-1427, which allows\n \
  attackers to leverage features of this API to gain unauthenticated remote code\n \
  execution (RCE).\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2015-1427.html;\
  ;http-vuln-cve2015-1427;--script=http-vuln-cve2015-1427 --script-args command='ls'" \
  #
  "Checks for a remote code execution vulnerability (MS15-034) in Microsoft\n \
  Windows systems (CVE2015-2015-1635).\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2015-1635.html;\
  ;http-vuln-cve2015-1635-1;-sV --script vuln" \
  #
  "Checks for a remote code execution vulnerability (MS15-034) in Microsoft\n \
  Windows systems (CVE2015-2015-1635).\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2015-1635.html;\
  ;http-vuln-cve2015-1635-2;--script http-vuln-cve2015-1635.nse -p 80" \
  #
  "Checks for a remote code execution vulnerability (MS15-034) in Microsoft\n \
  Windows systems (CVE2015-2015-1635).\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2015-1635.html;\
  ;http-vuln-cve2015-1635-3;-sV --script http-vuln-cve2015-1635 --script-args uri='/anotheruri/'" \
  #
  "Attempts to detect a privilege escalation vulnerability in Wordpress 4.7.0\n \
  and 4.7.1 that allows unauthenticated users to inject content in posts.\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2017-1001000.html;\
  ;http-vuln-cve2017-1001000-1;--script http-vuln-cve2017-1001000" \
  #
  "Attempts to detect a privilege escalation vulnerability in Wordpress 4.7.0\n \
  and 4.7.1 that allows unauthenticated users to inject content in posts.\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2017-1001000.html;\
  ;http-vuln-cve2017-1001000-2;--script http-vuln-cve2017-1001000 --script-args http-vuln-cve2017-1001000=\"uri\"" \
  #
  "Detects whether the specified URL is vulnerable to the Apache Struts Remote\n \
  Code Execution Vulnerability (CVE-2017-5638).\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2017-5638.html;\
  ;http-vuln-cve2017-5638;--script http-vuln-cve2017-5638 -p 80" \
  #
  "An SQL Injection vulnerability affecting Joomla! 3.7.x before 3.7.1 allows\n \
  for unauthenticated users to execute arbitrary SQL commands. This\n \
  vulnerability was caused by a new component, com_fields, which was introduced\n \
  in version 3.7. This component is publicly accessible, which means this can be\n \
  exploited by any malicious individual visiting the site.\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2017-8917.html;\
  ;http-vuln-cve2017-8917-1;--script http-vuln-cve2017-8917 -p 80" \
  #
  "An SQL Injection vulnerability affecting Joomla! 3.7.x before 3.7.1 allows\n \
  for unauthenticated users to execute arbitrary SQL commands. This\n \
  vulnerability was caused by a new component, com_fields, which was introduced\n \
  in version 3.7. This component is publicly accessible, which means this can be\n \
  exploited by any malicious individual visiting the site.\n \
  \n https://nmap.org/nsedoc/scripts/http-vuln-cve2017-8917.html;\
  ;http-vuln-cve2017-8917-2;--script http-vuln-cve2017-8917 --script-args http-vuln-cve2017-8917.uri=joomla/ -p 80" \
  #
  "Enumerates usernames in Wordpress blog/CMS installations by exploiting an\n \
  information disclosure vulnerability existing in versions 2.6, 3.1, 3.1.1,\n \
  3.1.3 and 3.2-beta2 and possibly others.\n \
  \n https://nmap.org/nsedoc/scripts/http-wordpress-users.html;\
  ;http-wordpress-users-1;--script http-wordpress-users -p 80" \
  #
  "Enumerates usernames in Wordpress blog/CMS installations by exploiting an\n \
  information disclosure vulnerability existing in versions 2.6, 3.1, 3.1.1,\n \
  3.1.3 and 3.2-beta2 and possibly others.\n \
  \n https://nmap.org/nsedoc/scripts/http-wordpress-users.html;\
  ;http-wordpress-users-2;-sV --script http-wordpress-users --script-args limit=50" \
  #
  "Detects if naive signing is enabled on a Puppet server. This enables\n \
  attackers to create any Certificate Signing Request and have it signed,\n \
  allowing them to impersonate as a puppet agent. This can leak the\n \
  configuration of the agents as well as any other sensitive information found\n \
  in the configuration files.\n \
  \n https://nmap.org/nsedoc/scripts/puppet-naivesigning.html;\
  ;puppet-naivesigning-1;--script puppet-naivesigning -p 8140" \
  #
  "Detects if naive signing is enabled on a Puppet server. This enables\n \
  attackers to create any Certificate Signing Request and have it signed,\n \
  allowing them to impersonate as a puppet agent. This can leak the\n \
  configuration of the agents as well as any other sensitive information found\n \
  in the configuration files.\n \
  \n https://nmap.org/nsedoc/scripts/puppet-naivesigning.html;\
  ;puppet-naivesigning-2;--script puppet-naivesigning --script-args puppet-naivesigning.csr=other.csr,puppet-naivesigning.node=agency -p 8140" \
  #
  "Checks if a VNC server is vulnerable to the RealVNC authentication bypass\n \
  (CVE-2006-2369).\n \
  \n https://nmap.org/nsedoc/scripts/realvnc-auth-bypass.html;\
  ;realvnc-auth-bypass;-sV --script=realvnc-auth-bypass" \
  #
  "Detects RSA keys vulnerable to Return Of Coppersmith Attack (ROCA)\n \
  factorization.\n \
  \n https://nmap.org/nsedoc/scripts/rsa-vuln-roca.html;\
  ;rsa-vuln-roca;--script rsa-vuln-roca -p 22,443" \
  #
  "Checks if target machines are vulnerable to the Samba heap overflow\n \
  vulnerability CVE-2012-1182.\n \
  \n https://nmap.org/nsedoc/scripts/samba-vuln-cve-2012-1182.html;\
  ;samba-vuln-cve-2012-1182;--script=samba-vuln-cve-2012-1182 -p 139" \
  #
  "Checks if the target machine is running the Double Pulsar SMB backdoor.\n \
  \n https://nmap.org/nsedoc/scripts/smb-double-pulsar-backdoor.html;\
  ;smb-double-pulsar-backdoor;--script=smb-double-pulsar-backdoor -p 445"\
  #
  "Detects Microsoft Windows systems infected by the Conficker worm. This check\n \
  is dangerous and it may crash systems.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-conficker.html;\
  ;smb-vuln-conficker-1;-sU --script smb-vuln-conficker.nse -p T:139" \
  #
  "Detects Microsoft Windows systems infected by the Conficker worm. This check\n \
  is dangerous and it may crash systems.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-conficker.html;\
  ;smb-vuln-conficker-2;--script smb-vuln-conficker.nse -p 445" \
  #
  "Checks if target machines are vulnerable to the arbitrary shared library load\n \
  vulnerability CVE-2017-7494.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-cve-2017-7494.html;\
  ;smb-vuln-cve-2017-7494-1;--script smb-vuln-cve-2017-7494 -p 445" \
  #
  "Checks if target machines are vulnerable to the arbitrary shared library load\n \
  vulnerability CVE-2017-7494.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-cve-2017-7494.html;\
  ;smb-vuln-cve-2017-7494-2;--script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p 445" \
  #
  "Detects Microsoft Windows systems vulnerable to denial of service\n \
  (CVE-2009-3103). This script will crash the service if it is vulnerable.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-cve2009-3103.html;\
  ;smb-vuln-cve2009-3103-1;--script smb-vuln-cve2009-3103.nse -p 445" \
  #
  "Detects Microsoft Windows systems vulnerable to denial of service\n \
  (CVE-2009-3103). This script will crash the service if it is vulnerable.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-cve2009-3103.html;\
  ;smb-vuln-cve2009-3103-2;-sU --script smb-vuln-cve2009-3103.nse -p U:137,T:139" \
  #
  "Detects Microsoft Windows systems with Dns Server RPC vulnerable to\n \
  MS07-029.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-ms07-029.html;\
  ;smb-vuln-ms07-029-1;--script smb-vuln-ms07-029.nse -p 445" \
  #
  "Detects Microsoft Windows systems with Dns Server RPC vulnerable to\n \
  MS07-029.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-ms07-029.html;\
  ;smb-vuln-ms07-029-2;-sU --script smb-vuln-ms07-029.nse -p U:137,T:139" \
  #
  "Detects Microsoft Windows systems vulnerable to the remote code execution\n \
  vulnerability known as MS08-067. This check is dangerous and it may crash\n \
  systems.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-ms08-067.html;\
  ;smb-vuln-ms08-067-1;--script smb-vuln-ms08-067.nse -p 445" \
  #
  "Detects Microsoft Windows systems vulnerable to the remote code execution\n \
  vulnerability known as MS08-067. This check is dangerous and it may crash\n \
  systems.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-ms08-067.html;\
  ;smb-vuln-ms08-067-2;-sU --script smb-vuln-ms08-067.nse -p U:137" \
  #
  "Tests whether target machines are vulnerable to the ms10-054 SMB remote\n \
  memory corruption vulnerability.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-ms10-054.html;\
  ;smb-vuln-ms10-054;--script=smb-vuln-ms10-054 --script-args unsafe -p 445" \
  #
  "Tests whether target machines are vulnerable to ms10-061 Printer Spooler\n \
  impersonation vulnerability.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-ms10-061.html;\
  ;smb-vuln-ms10-061;<target> --script=smb-vuln-ms10-061 -p 445" \
  #
  "Attempts to detect if a Microsoft SMBv1 server is vulnerable to a remote code\n \
  execution vulnerability (ms17-010, a.k.a. EternalBlue). The vulnerability is\n \
  actively exploited by WannaCry and Petya ransomware and other malware.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html;\
  ;smb-vuln-ms17-010-1;--script vuln -p 445" \
  #
  "Attempts to detect if a Microsoft SMBv1 server is vulnerable to a remote code\n \
  execution vulnerability (ms17-010, a.k.a. EternalBlue). The vulnerability is\n \
  actively exploited by WannaCry and Petya ransomware and other malware.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html;\
  ;smb-vuln-ms17-010-2;--script smb-vuln-ms17-010 -p 445" \
  #
  "Checks if a Microsoft Windows 2000 system is vulnerable to a crash in regsvc\n \
  caused by a null pointer dereference. This check will crash the service if it\n \
  is vulnerable and requires a guest account or higher to work.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-regsvc-dos.html;\
  ;smb-vuln-regsvc-dos-1;--script smb-vuln-regsvc-dos.nse -p 445" \
  #
  "Checks if a Microsoft Windows 2000 system is vulnerable to a crash in regsvc\n \
  caused by a null pointer dereference. This check will crash the service if it\n \
  is vulnerable and requires a guest account or higher to work.\n \
  \n https://nmap.org/nsedoc/scripts/smb-vuln-regsvc-dos.html;\
  ;smb-vuln-regsvc-dos-2;-sU --script smb-vuln-regsvc-dos.nse -p U:137,T:139" \
  #
  "Attempts to detect missing patches in Windows systems by checking the uptime\n \
  returned during the SMB2 protocol negotiation.\n \
  \n https://nmap.org/nsedoc/scripts/smb2-vuln-uptime.html;\
  ;smb2-vuln-uptime-1;-O --script smb2-vuln-uptime" \
  #
  "Attempts to detect missing patches in Windows systems by checking the uptime\n \
  returned during the SMB2 protocol negotiation.\n \
  \n https://nmap.org/nsedoc/scripts/smb2-vuln-uptime.html;\
  ;smb2-vuln-uptime-2;--script smb2-vuln-uptime --script-args smb2-vuln-uptime.skip-os=true -p 445" \
  #
  "Checks for and/or exploits a heap overflow within versions of Exim prior to\n \
  version 4.69 (CVE-2010-4344) and a privilege escalation vulnerability in Exim\n \
  4.72 and prior (CVE-2010-4345).\n \
  \n https://nmap.org/nsedoc/scripts/smtp-vuln-cve2010-4344.html;\
  ;smtp-vuln-cve2010-4344-1;--script=smtp-vuln-cve2010-4344 --script-args=\"smtp-vuln-cve2010-4344.exploit\" -p T:25,465,587" \
  #
  "Checks for and/or exploits a heap overflow within versions of Exim prior to\n \
  version 4.69 (CVE-2010-4344) and a privilege escalation vulnerability in Exim\n \
  4.72 and prior (CVE-2010-4345).\n \
  \n https://nmap.org/nsedoc/scripts/smtp-vuln-cve2010-4344.html;\
  ;smtp-vuln-cve2010-4344-2;--script=smtp-vuln-cve2010-4344 --script-args=\"exploit.cmd='uname -a'\" -p T:25,465,587" \
  #
  "Checks for a memory corruption in the Postfix SMTP server when it uses Cyrus\n \
  SASL library authentication mechanisms (CVE-2011-1720). This vulnerability can\n \
  allow denial of service and possibly remote code execution.\n \
  \n https://nmap.org/nsedoc/scripts/smtp-vuln-cve2011-1720.html;\
  ;smtp-vuln-cve2011-1720;--script=smtp-vuln-cve2011-1720 --script-args='smtp.domain=<domain>' -p T:25,465,587" \
  #
  "Checks for a format string vulnerability in the Exim SMTP server (version\n \
  4.70 through 4.75) with DomainKeys Identified Mail (DKIM) support\n \
  (CVE-2011-1764). The DKIM logging mechanism did not use format string\n \
  specifiers when logging some parts of the DKIM-Signature header field. A\n \
  remote attacker who is able to send emails, can exploit this vulnerability and\n \
  execute arbitrary code with the privileges of the Exim daemon.\n \
  \n https://nmap.org/nsedoc/scripts/smtp-vuln-cve2011-1764.html;\
  ;smtp-vuln-cve2011-1764;--script=smtp-vuln-cve2011-1764 -p T:25,465,587" \
  #
  "Detects whether a server is vulnerable to the SSL/TLS \"CCS Injection\"\n \
  vulnerability (CVE-2014-0224), first discovered by Masashi Kikuchi. The script\n \
  is based on the ccsinjection.c code authored by Ramon de C Valle\n \
  (https://gist.github.com/rcvalle/71f4b027d61a78c42607).\n \
  \n https://nmap.org/nsedoc/scripts/ssl-ccs-injection.html;\
  ;ssl-ccs-injection;--script ssl-ccs-injection -p 443" \
  #
  "Reports any private (RFC1918) IPv4 addresses found in the various fields of\n \
  an SSL service's certificate. These will only be reported if the target\n \
  address itself is not private. Nmap v7.30 or later is required.\n \
  \n https://nmap.org/nsedoc/scripts/ssl-cert-intaddr.html;\
  ;ssl-cert-intaddr;--script ssl-cert-intaddr -p 443" \
  #
  "Weak ephemeral Diffie-Hellman parameter detection for SSL/TLS services.\n \
  \n https://nmap.org/nsedoc/scripts/ssl-dh-params.html;\
  ;ssl-dh-params;--script ssl-dh-params" \
  #
  "Detects whether a server is vulnerable to the OpenSSL Heartbleed bug\n \
  (CVE-2014-0160). The code is based on the Python script ssltest.py authored by\n \
  Jared Stafford (jspenguin@jspenguin.org).\n \
  \n https://nmap.org/nsedoc/scripts/ssl-heartbleed.html;\
  ;ssl-heartbleed;--script ssl-heartbleed -p 443" \
  #
  "Detects whether a server is vulnerable to the OpenSSL Heartbleed bug\n \
  (CVE-2014-0160). The code is based on the Python script ssltest.py authored by\n \
  Jared Stafford (jspenguin@jspenguin.org).\n \
  \n https://nmap.org/nsedoc/scripts/ssl-known-key.html;\
  ;ssl-known-key;--script ssl-known-key -p 443" \
  #
  "Checks whether SSLv3 CBC ciphers are allowed (POODLE).\n \
  \n https://nmap.org/nsedoc/scripts/ssl-poodle.html;\
  ;ssl-poodle;-sV --version-light --script ssl-poodle -p 443" \
  #
  "Determines whether the server supports SSLv2, what ciphers it supports and\n \
  tests for CVE-2015-3197, CVE-2016-0703 and CVE-2016-0800 (DROWN).\n \
  \n https://nmap.org/nsedoc/scripts/sslv2-drown.html;\
  ;sslv2-drown;-sV --script=sslv2-drown" \
  #
  "Detects whether a server is vulnerable to the F5 Ticketbleed bug\n \
  (CVE-2016-9244).\n \
  \n https://nmap.org/nsedoc/scripts/tls-ticketbleed.html;\
  ;tls-ticketbleed;--script tls-ticketbleed -p 443" \
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
