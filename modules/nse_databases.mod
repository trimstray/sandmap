#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: nse_databases()
#
# Description:
#   NSE Databases Service Module.
#
# Usage:
#   nse_databases
#
# Examples:
#   nse_databases
#

function nse_databases() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="nse_databases"
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
  description="NSE Databases Service Module"

  # shellcheck disable=SC2034,SC2154
  _module_cfg="${_modules}/${module_name}.cfg"

  touch "$_module_cfg"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description
    -----------

      NSE Databases Service Module.

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

  # shellcheck disable=SC2034
  _module_commands=(\
  #
  "https://nmap.org/nsedoc/scripts/couchdb-databases.html;\
  ;couchdb-databases;--script couchdb-databases" \
  #
  "https://nmap.org/nsedoc/scripts/couchdb-stats.html;\
  ;couchdb-stats;--script couchdb-stats" \
  #
  "https://nmap.org/nsedoc/scripts/db2-das-info.html;\
  ;db2-das-info;--script db2-das-info" \
  #
  "https://nmap.org/nsedoc/scripts/membase-brute.html;\
  ;membase-brute;--script membase-brute" \
  #
  "https://nmap.org/nsedoc/scripts/membase-http-info.html;\
  ;membase-http-info;--script membase-http-info" \
  #
  "https://nmap.org/nsedoc/scripts/mongodb-brute.html;\
  ;mongodb-brute;--script mongodb-brute" \
  #
  "https://nmap.org/nsedoc/scripts/mongodb-databases.html;\
  ;mongodb-databases;--script mongodb-databases" \
  #
  "https://nmap.org/nsedoc/scripts/mongodb-info.html;\
  ;mongodb-info;--script mongodb-info" \
  #
  "https://nmap.org/nsedoc/scripts/ms-sql-brute.html;\
  ;ms-sql-brute;--script ms-sql-brute" \
  #
  "https://nmap.org/nsedoc/scripts/ms-sql-config.html;\
  ;ms-sql-config;--script ms-sql-config" \
  #
  "https://nmap.org/nsedoc/scripts/ms-sql-dac.html;\
  ;ms-sql-dac;--script ms-sql-dac" \
  #
  "https://nmap.org/nsedoc/scripts/ms-sql-dump-hashes.html;\
  ;ms-sql-dump-hashes;--script ms-sql-dump-hashes" \
  #
  "https://nmap.org/nsedoc/scripts/ms-sql-empty-password.html;\
  ;ms-sql-empty-password;--script ms-sql-empty-password" \
  #
  "https://nmap.org/nsedoc/scripts/ms-sql-hasdbaccess.html;\
  ;ms-sql-hasdbaccess;--script ms-sql-hasdbaccess" \
  #
  "https://nmap.org/nsedoc/scripts/ms-sql-info.html;\
  ;ms-sql-info;--script ms-sql-info" \
  #
  "https://nmap.org/nsedoc/scripts/ms-sql-ntlm-info.html;\
  ;ms-sql-ntlm-info;--script ms-sql-ntlm-info" \
  #
  "https://nmap.org/nsedoc/scripts/ms-sql-query.html;\
  ;ms-sql-query;--script ms-sql-query" \
  #
  "https://nmap.org/nsedoc/scripts/ms-sql-tables.html;\
  ;ms-sql-tables;--script ms-sql-tables" \
  #
  "https://nmap.org/nsedoc/scripts/ms-sql-xp-cmdshell.html;\
  ;ms-sql-xp-cmdshell;--script ms-sql-xp-cmdshell" \
  #
  "https://nmap.org/nsedoc/scripts/mysql-audit.html;\
  ;mysql-audit;--script mysql-audit" \
  #
  "https://nmap.org/nsedoc/scripts/mysql-brute.html;\
  ;mysql-brute;--script mysql-brute" \
  #
  "https://nmap.org/nsedoc/scripts/mysql-databases.html;\
  ;mysql-databases;--script mysql-databases" \
  #
  "https://nmap.org/nsedoc/scripts/mysql-dump-hashes.html;\
  ;mysql-dump-hashes;--script mysql-dump-hashes" \
  #
  "https://nmap.org/nsedoc/scripts/mysql-empty-password.html;\
  ;mysql-empty-password;--script mysql-empty-password" \
  #
  "https://nmap.org/nsedoc/scripts/mysql-enum.html;\
  ;mysql-enum;--script mysql-enum" \
  #
  "https://nmap.org/nsedoc/scripts/mysql-info.html;\
  ;mysql-info;--script mysql-info" \
  #
  "https://nmap.org/nsedoc/scripts/mysql-query.html;\
  ;mysql-query;--script mysql-query" \
  #
  "https://nmap.org/nsedoc/scripts/mysql-users.html;\
  ;mysql-users;--script mysql-users" \
  #
  "https://nmap.org/nsedoc/scripts/mysql-variables.html;\
  ;mysql-variables;--script mysql-variables" \
  #
  "https://nmap.org/nsedoc/scripts/mysql-vuln-cve2012-2122.html;\
  ;mysql-vuln-cve2012-2122;--script mysql-vuln-cve2012-2122" \
  #
  "https://nmap.org/nsedoc/scripts/pgsql-brute.html;\
  ;pgsql-brute;--script pgsql-brute" \
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
