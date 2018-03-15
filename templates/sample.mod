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

  category="scanning"

  # shellcheck disable=SC2154
  echo "$module_name ${module_args[*]} $category"

  return $_STATE

}
