#!/usr/bin/env bash

readonly _dir="$(dirname "$(readlink -f "$0")")"

# shellcheck disable=SC2034
_arg="$1"

if [[ "$1" == "install" ]] ; then

  printf "%s\n" "Create symbolic link to /usr/local/bin"

  if [[ -e "${_dir}/bin/sandmap" ]] ; then

    if [[ ! -e "/usr/local/bin/sandmap" ]] ; then

      ln -s "${_dir}/bin/sandmap" /usr/local/bin

    fi

  fi

  printf "%s\n" "Create man page to /usr/local/man/man8"

  if [[ -e "${_dir}/doc/man8/sandmap.8" ]] ; then

    if [[ ! -e "/usr/local/man/man8/sandmap.8.gz" ]] ; then

      cp "${_dir}/doc/man8/sandmap.8" /usr/local/man/man8
      gzip /usr/local/man/man8/sandmap.8

    fi

  fi

elif [[ "$1" == "uninstall" ]] ; then

  printf "%s\n" "Remove symbolic link from /usr/local/bin"

  if [[ -L "/usr/local/bin/sandmap" ]] ; then

    unlink /usr/local/bin/sandmap

  fi

  printf "%s\n" "Remove man page from /usr/local/man/man8"

  if [[ -e "/usr/local/man/man8/sandmap.8.gz" ]] ; then

    rm /usr/local/man/man8/sandmap.8.gz

  fi

fi

exit 0
