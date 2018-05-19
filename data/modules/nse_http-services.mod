#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_http-services()
#
# Description:
#   NSE HTTP Services Module.
#
# Usage:
#   nse_http-services
#
# Examples:
#   nse_http-services
#

function nse_http-services() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_http-services"
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
  description="NSE HTTP Services Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s: \\e[1;32m%s\\e[m" "
  Module" "${module_name}")

  _module_help+=$(printf "%s" "

    Description
    -----------

      NSE HTTP Services Module.

    Commands
    --------

      help    <module>                display module or NSE help
      show    <key>                   display module or profile info
      config  <key>                   show module configuration
      set     <key>                   set module variable value
      use     <module>                reuse module (changed env)
      pushd   <key>|init|show|flush   command line commands stack
      search  <key>                   search key in all commands
      init    <alias|id> [--args]     run profile

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

        printf "_module_variables=(\"%s\")\\n" "${_module_variables[@]}" > "$_module_cfg"

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
  "https://nmap.org/nsedoc/scripts/http-apache-negotiation.html;\
  ;http-apache-negotiation;--script=http-apache-negotiation;\
  \"http-apache-negotiation.root=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-apache-server-status.html;\
  ;http-apache-server-status;--script=http-apache-server-status" \
  #
  "https://nmap.org/nsedoc/scripts/http-aspnet-debug.html;\
  ;http-aspnet-debug;--script=http-aspnet-debug;\
  \"http-aspnet-debug.path=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-awstatstotals-exec.html;\
  ;http-awstatstotals-exec;--script=http-awstatstotals-exec;\
  \"http-awstatstotals-exec.uri=index.php\",\"http-awstatstotals-exec.cmd=whoami\",\
  \"http-awstatstotals-exec.outfile\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-bigip-cookie.html;\
  ;http-bigip-cookie;--script=http-bigip-cookie;\
  \"http-bigip-cookie.path=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-cakephp-version.html;\
  ;http-cakephp-version;--script=http-cakephp-version" \
  #
  "https://nmap.org/nsedoc/scripts/http-dlink-backdoor.html;\
  ;http-dlink-backdoor;--script=http-dlink-backdoor" \
  #
  "https://nmap.org/nsedoc/scripts/http-drupal-enum.html;\
  ;http-drupal-enum;--script=http-drupal-enum;\
  \"http-drupal-enum.themes_path\",\"http-drupal-enum.number=100\",\
  \"http-drupal-enum.type=all.choose\",\"http-drupal-enum.root=/\",\
  \"http-drupal-enum.modules_path\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-drupal-enum-users.html;\
  ;http-drupal-enum-users;--script=http-drupal-enum-users;\
  \"http-drupal-enum-users.root=100\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-git.html;\
  ;http-git;--script=http-git;\
  \"http-git.root=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-iis-short-name-brute.html;\
  ;http-iis-short-name-brute;--script=http-iis-short-name-brute" \
  #
  "https://nmap.org/nsedoc/scripts/http-iis-webdav-vuln.html;\
  ;http-iis-webdav-vuln;--script=http-iis-webdav-vuln;\
  \"basefolder\",\"folderdb\",\"webdavfolder\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-joomla-brute.html;\
  ;http-joomla-brute;--script=http-joomla-brute;\
  \"http-joomla-brute.uservar=username\",\"http-joomla-brute.threads=3\",\
  \"http-joomla-brute.uri=/administrator/index.php\",\"http-joomla-brute.hostname\",\
  \"http-joomla-brute.passvar=passwd\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-jsonp-detection.html;\
  ;http-jsonp-detection;--script=http-jsonp-detection;\
  \"http-jsonp-detection.path=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-malware-host.html;\
  ;http-malware-host;--script=http-malware-host" \
  #
  "https://nmap.org/nsedoc/scripts/http-passwd.html;\
  ;http-passwd;--script=http-passwd;\
  \"http-passwd.root=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-php-version.html;\
  ;http-php-version;--script=http-php-version" \
  #
  "https://nmap.org/nsedoc/scripts/http-phpmyadmin-dir-traversal.html;\
  ;http-phpmyadmin-dir-traversal;--script=http-phpmyadmin-dir-traversal;\
  \"http-phpmyadmin-dir-traversal.dir=/phpMyAdmin-2.6.4-pl1/\",\
  \"http-phpmyadmin-dir-traversal.file=../../../../../etc/passwd\",\
  \"http-phpmyadmin-dir-traversal.outfile\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-robots.txt.html;\
  ;http-robots;--script=http-robots.txt" \
  #
  "https://nmap.org/nsedoc/scripts/http-tplink-dir-traversal.html;\
  ;http-tplink-dir-traversal;--script=http-tplink-dir-traversal;\
  \"http-tplink-dir-traversal.rfile=/etc/passwd\",\"http-tplink-dir-traversal.outfile\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-virustotal.html;\
  ;http-virustotal;--script=http-virustotal;\
  \"http-virustotal.checksum\",\"http-virustotal.apikey\",\
  \"http-virustotal.upload=false\",\"http-virustotal.filename\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-vmware-path-vuln.html;\
  ;http-vmware-path-vuln;--script=http-vmware-path-vuln" \
  #
  "https://nmap.org/nsedoc/scripts/http-waf-detect.html;\
  ;http-waf-detect;--script=http-waf-detect;\
  \"http-waf-detect.uri\",\"http-waf-detect.aggro\",\
  \"http-waf-detect.detectBodyChanges\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-waf-fingerprint.html;\
  ;http-waf-fingerprint;--script=http-waf-fingerprint;\
  \"http-waf-fingerprint.root=/\",\"http-waf-fingerprint.intensive\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-webdav-scan.html;\
  ;http-webdav-scan;--script=http-webdav-scan;\
  \"http-webdav-scan.path=/\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-wordpress-brute.html;\
  ;http-wordpress-brute;--script=http-wordpress-brute;\
  \"http-wordpress-brute.threads=3\",\"http-wordpress-brute.uri=/wp-login.php\",\
  \"http-wordpress-brute.uservar=log\",\"http-wordpress-brute.hostname\",\
  \"http-wordpress-brute.passvar=pwd\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-wordpress-enum.html;\
  ;http-wordpress-enum;--script=http-wordpress-enum;\
  \"http-wordpress-enum.type=all\",\"http-wordpress-enum.search-limit=100\",\
  \"http-wordpress-enum.root=/\",\"http-wordpress-enum.check-latest=false\"" \
  #
  "https://nmap.org/nsedoc/scripts/http-wordpress-users.html;\
  ;http-wordpress-users;--script=http-wordpress-users;\
  \"http-wordpress-users.out\",\"http-wordpress-users.basepath=/\",\
  \"http-wordpress-users.limit=25\"" \
  )

  # shellcheck disable=SC2034,SC2154
  _module_show=(\
      "${module_name}" \
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
