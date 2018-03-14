#!/usr/bin/env bash

# shellcheck shell=bash

# ``````````````````````````````````````````````````````````````````````````````
# Function name: sample_module()
#
# Description:
#   Sample module.
#
# Usage:
#   sample_module
#
# Examples:
#   sample_module
#

function sample_module() {

  # shellcheck disable=SC2034
  local _FUNCTION_ID="sample_module"
  local _STATE=0

  echo "sample ok"

  return $_STATE

}

sample_module
