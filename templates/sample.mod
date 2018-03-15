#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: sample()
#
# Description:
#   Sample module.
#
# Usage:
#   sample
#
# Examples:
#   sample
#

function sample() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="sample"
  local _STATE=0

  # User variables:
  # - module_name: store module name
  # - module_args: store module arguments

  # shellcheck disable=SC2034
  author="example"
  contact="example@example.com"
  version="1.0"
  category="scanning"

  # shellcheck disable=SC2034,SC2154
  _module_help=$(printf "%s" "
  Module: ${module_name}

    Description:

      It's a sample module template - short description.

    Options:

      show
        config  <file|user|port|web|db>
        cluster <status|databases>

      set
        config  <file|user|port|web[add,del]|db[add,del]>
        cluster <attach{all|[host][db]}|{all|detach[host][db]}>

    Examples:

      show config                     displays the entire configuration
      show config user                show username key
      show cluster status             show cluster status
      set config user admin           set username key to 'admin'
      set cluster web add web1-node   added web1-node host to web key
      set cluster db del db1-node     deleted db1-node host from db key
      set cluster attach web1-node 0  attach web1-node to the db
                                      marked with 0 id
      set cluster detach web1-node 1  detach web1-node from the db
                                      marked with 1 id
      set cluster attach all 1        attach all nodes to the db
                                      marked with 1 id
")

  # shellcheck disable=SC2034,SC2154
  _module_show=$(printf "%s" "
    Module: ${module_name}
    Author: ${author}
   Contact: ${contact}
   Version: ${version}
  Category: ${category}
")

  # shellcheck disable=SC2034
  _module_opts=(\
  "$_module_help" \
  "$_module_show")

  return $_STATE

}
