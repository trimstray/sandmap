<h1 align="center">Sandmap</h1>

<h4 align="center">Sandmap is a tool supporting network and system reconnaissance using the massive Nmap engine.</h4>

<p align="center">
  <a href="https://img.shields.io/badge/Branch-master-green.svg">
    <img src="https://img.shields.io/badge/Branch-master-green.svg"
        alt="Branch">
  </a>
  <a href="https://img.shields.io/badge/Version-v1.2.0-lightgrey.svg">
    <img src="https://img.shields.io/badge/Version-v1.2.0-lightgrey.svg"
        alt="Version">
  </a>
  <a href="https://img.shields.io/badge/Modules-31-red.svg">
    <img src="https://img.shields.io/badge/Modules-31-red.svg"
        alt="Modules">
  </a>
  <a href="https://img.shields.io/badge/Profiles-459-orange.svg">
    <img src="https://img.shields.io/badge/Profiles-459-orange.svg"
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
 • <a href="#cli">CLI</a>
 • <a href="#configuration">Configuration</a>
 • <a href="#requirements">Requirements</a>
 • <a href="#modules">Modules</a>
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
    <img src="/doc/img/sandmap_v1.2.0.gif?raw=true"
         alt="Master">
</p>

## Description

**<u>Sandmap</u>** is a tool supporting network and system reconnaissance using the massive **Nmap engine**. It provides a user-friendly interface, automates and speeds up scanning and allows you to easily use many advanced scanning techniques.

### Key Features

- simple **CLI** with the ability to run pure **Nmap engine**
- predefined scans included in the **modules**
- support **Nmap Scripting Engine** (NSE) with scripts arguments
- **TOR** support (with proxychains)
- multiple scans at one time
- at this point: **31** modules with **459** scan profiles

## How To Use

It's simple:

```bash
# Clone this repository
git clone --recursive https://github.com/trimstray/sandmap

# Go into the repository
cd sandmap

# Install
./setup.sh install

# Run the app
sandmap
```

> * symlink to `bin/sandmap` is placed in `/usr/local/bin`
> * man page is placed in `/usr/local/man/man8`

## CLI

Before using the Sandmap read the <a href="https://github.com/trimstray/sandmap/wiki/CLI">CLI manual</a>.

## Configuration

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

This tool working with:

- **GNU/Linux** or **BSD** (testing on Debian, CentOS and FreeBSD)
- **Bash** (testing on 4.4.19)
- **Nmap** (testing on 7.70)

Also you will need **root access**.

## Modules

Available modules: **31**  
Available scan profiles: **459**

> If you want to create your own modules, take a look **[this](https://github.com/trimstray/sandmap/wiki/Modules)**.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Project architecture

See <a href="https://github.com/trimstray/sandmap/wiki/Project-architecture">Project Architecture</a>.

## License

GPLv3 : <http://www.gnu.org/licenses/>

**Free software, Yeah!**
