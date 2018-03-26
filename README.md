<h1 align="center">Sandmap</h1>

<h4 align="center">Sandmap is a tool supporting network and system reconnaissance using the massive Nmap engine.</h4>

<p align="center">
  <a href="https://img.shields.io/badge/Branch-master-green.svg">
    <img src="https://img.shields.io/badge/Branch-master-green.svg"
        alt="Branch">
  </a>
  <a href="https://img.shields.io/badge/Version-v1.0.3-lightgrey.svg">
    <img src="https://img.shields.io/badge/Version-v1.0.3-lightgrey.svg"
        alt="Version">
  </a>
  <a href="https://img.shields.io/badge/Modules-7-red.svg">
    <img src="https://img.shields.io/badge/Modules-7-red.svg"
        alt="Modules">
  </a>
  <a href="https://img.shields.io/badge/Profiles-174-orange.svg">
    <img src="https://img.shields.io/badge/Profiles-174-orange.svg"
        alt="Profiles">
  </a>
  <a href="https://travis-ci.org/trimstray/sandmap">
    <img src="https://travis-ci.org/trimstray/sandmap.svg?branch=master"
        alt="Travis-CI">
  <a href="http://www.gnu.org/licenses/">
    <img src="https://img.shields.io/badge/license-GNU-blue.svg"
        alt="License">
  </a>
</p>

<p align="center">
   <a href="#description">Description</a>
 • <a href="#how-to-use">How To Use</a>
 • <a href="#modules">Modules</a>
 • <a href="#configuration-file">Configuration File</a>
 • <a href="#requirements">Requirements</a>
 • <a href="#logging">Logging</a>
 • <a href="#contributing">Contributing</a>
 • <a href="#project-architecture">Project Architecture</a>
 • <a href="#license">License</a>
 • <a href="https://github.com/trimstray/sandmap/wiki">Wiki</a>
</p>

<div align="center">
  <sub>Created by
  <a href="https://twitter.com/trimstray">trimstray</a> and
  <a href="https://github.com/trimstray/sandmap/graphs/contributors">
    contributors
  </a>
</div>

<br>

<p align="center">
    <img src="https://i.imgur.com/6yw3YzJ.gif"
        alt="Master">
</p>

## Description

**Sandmap** is a tool supporting network and system reconnaissance using the massive **Nmap engine**. It provides a user-friendly interface, automates and speeds up scanning and allows you to easily use many advanced scanning techniques.

### Key Features

- simple **CLI** with the ability to run pure **Nmap engine**
- predefined scans included in the **modules**
- support **Nmap Scripting Engine** (NSE)
- **TOR** support (with proxychains)
- multiple scans at one time
- at this point: **7** modules with **174** scan profiles

## How To Use

It's simple:

```bash
# Clone this repository
git clone https://github.com/trimstray/sandmap

# Go into the repository
cd sandmap

# Install
./setup.sh install

# Run the app
sandmap
```

> * symlink to `bin/sandmap` is placed in `/usr/local/bin`
> * man page is placed in `/usr/local/man/man8`

## Modules

Available modules: **7**  
Available scan profiles: **174**

NSE Modules: **2**  
NSE Profiles: **133**

## Configuration file

The `etc/main.cfg` configuration file has the following structure:

```bash
# shellcheck shell=bash

# Specifies the default destination.
# Examples:
#   - dest="127.0.0.1,8.8.8.8"
dest="127.0.0.1"

# Specifies the extended Nmap parameters.
# Examples:
#   - params="--script ssl-ccs-injection -p 443"
params=""

# Specifies the default output type and path.
# Examples:
#   - report="xml"
report=""

# Specifies the TOR connection.
# Examples:
#   - tor="true"
tor=""

# Specifies the terminal type.
# Examples:
#   - terminal="internal"
terminal="internal"
```

## Requirements

**<u>Sandmap</u>** uses external utilities to be installed before running:

- [nmap](https://nmap.org/)
- [xterm](https://invisible-island.net/xterm/)
- [proxychains](http://proxychains.sourceforge.net/)

## Logging

After running the script, the `log/` directory is created and in it the following files with logs:

* `<script_name>.<date>.log` - all `_logger()` function calls are saved in it
* `stdout.log` - a standard output and errors from the `_init_cmd()` function are written in it. If you want to redirect the output from command, use the following structure: `your_command >>"$_log_stdout" 2>&1 &`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Project architecture

    |-- LICENSE.md                 # GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007
    |-- README.md                  # this simple documentation
    |-- CONTRIBUTING.md            # principles of project support
    |-- .gitignore                 # ignore untracked files
    |-- .travis.yml                # continuous integration with Travis CI
    |-- setup.sh                   # install sandmap on the system
    |-- bin
        |-- sandmap                # main script (init)
    |-- doc                        # includes documentation, images and manuals
        |-- man8
            |-- sandmap.8          # man page for sandmap
        |-- img                    # images (eg. gif)
    |-- etc                        # contains configuration files
    |-- lib                        # libraries, external functions
    |-- log                        # contains logs, created after init
    |-- modules                    # contains modules
    |-- src                        # includes external project files
        |-- helpers                # contains core functions
        |-- import                 # appends the contents of the lib directory
        |-- __init__               # contains the __main__ function
        |-- settings               # contains sandmap settings
    |-- templates                  # contains examples and template files
    |-- tmp                        # contains temporary files (mktemp)

## License

GPLv3 : <http://www.gnu.org/licenses/>

**Free software, Yeah!**
