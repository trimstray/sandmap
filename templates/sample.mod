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

  # shellcheck disable=SC2034
  local module_name="$_FUNCTION_ID"
  local module_args=("${_argv[@]:1}")

  local category="scanning"

  return $_STATE

}
