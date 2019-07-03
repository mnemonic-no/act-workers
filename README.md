# ACT Workers

## Introduction

This repository contains workers for the [ACT platform](https://github.com/mnemonic-no/act-platform).

The source code the workers are available on [github](https://github.com/mnemonic-no/act-workers).

# Setup

To use the workers, install from PyPi:

```bash
sudo pip3 install act-workers
```

This will install scripts for all workers:

* act-argus-case
* act-attack
* act-country-regions
* act-misp-feeds
* act-mnemonic-pdns
* act-scio
* act-shadowserver-asn
* act-uploader
* act-url-shorter-unpack
* act-veris
* act-vt

# Usage

To print facts to stdout:

```bash
$ act-country-regions
{"type": "memberOf", "value": "", "accessMode": "Public", "sourceObject": {"type": "country", "value": "Afghanistan"}, "destinationObject": {"type": "subRegion", "value": "Southern Asia"}, "bidirectionalBinding": false}
{"type": "memberOf", "value": "", "accessMode": "Public", "sourceObject": {"type": "subRegion", "value": "Southern Asia"}, "destinationObject": {"type": "region", "value": "Asia"}, "bidirectionalBinding": false}
(...)
```

Or print facts as text representation:

```bash
$ act-country-regions --output-format str
(country/Afghanistan) -[memberOf]-> (subRegion/Southern Asia)
(subRegion/Southern Asia) -[memberOf]-> (region/Asia)
(...)
```

To add facts directly to the platform, include the act-baseurl and user-id options:

```bash
$ act-country-regions --act-baseurl http://localhost:8888 --user-id 1
```

# Configuration

All workers support options specified as command line arguments, environment variables and in a configuration file.

A utility to show and start with a default ini file is also included:

```bash
act-worker-config --help
usage: ACT worker config [-h] {show,user,system}

positional arguments:
  {show,user,system}

optional arguments:
  -h, --help          show this help message and exit

    show - Print default config

    user - Copy default config to /home/fredrikb/.config/actworkers/actworkers.ini

    system - Copy default config to /etc/actworkers.ini
```

You can see the default options in [act/workers/etc/actworkers.ini](act/workers/etc/actworkers.ini).

The configuration presedence are (from lowest to highest):
1. Defaults (shown in --help for each worker)
2. INI file
3. Environment variable
4. Command line argument

## INI-file
Arguments are parsed in two phases. First, it will look for the argument --config argument
which can be used to specify an alternative location for the ini file. If not --config argument
is given it will look for an ini file in the following locations:

    /etc/<CONFIG_FILE_NAME>
    ~/.config/<CONFIG_ID>/<CONFIG_FILE_NAME> (or directory specified by $XDG_CONFIG_HOME)

The ini file contains a "[DEFAULT]" section that will be used for all workers.
In addition there are separate sections for each worker which you can use to configure
worker-specific options, and override default options.

## Environment variables

The configuration step will also look for environment variables in uppercase and
with "-" replaced with "_". For the example for the option "cert-file" it will look for the
enviornment variable "$CERT_FILE".

## Requirements

All workers requires python version >= 3.5 and the act-api library:

* [act-api](https://github.com/mnemonic-no/act-api-python) (act-api on [pypi](https://pypi.org/project/act-api/))

In addition some of the libraries might have additional requirements. See requirements.txt for a full list of all requirements.

# Local development

Use pip to install in [local development mode](https://pip.pypa.io/en/stable/reference/pip_install/#editable-installs). act-workers (and act-api) uses namespacing, so it is not compatible with using `setup.py install` or `setup.py develop`.

In repository, run:

```bash
pip3 install --user -e .
```
