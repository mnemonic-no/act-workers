# ACT Workers

## Introduction

This repository contains workers for the [ACT platform](https://github.com/mnemonic-no/act-platform).

The source code the workers are available on [github](https://github.com/mnemonic-no/act-workers).

# Changelog

## 2.0.0

* Configuration is moved from `~/.config/actworkers/actworkers.ini` to `~/.config/act/act.ini`
* The old scio worker is removed and the new scio-worker (act-scio2) is renamed to act-scio

# Setup

To use the workers, install from PyPi:

```bash
sudo pip3 install act-workers
```

This will install scripts for all workers:

* act-argus-case
* act-attack
* act-country-regions
* act-fact-chain-helper (see usage below)
* act-feed
* act-ip-filter
* act-misp-feeds
* act-mnemonic-pdns
* act-scio
* act-search-graph
* act-shadowserver-asn
* act-uploader
* act-url-shorter-unpack
* act-ta-helper (see usage below)
* act-veris
* act-vt

# Origins

All workers support the optional arguments --origin-name and --origin-id. If they are not specified, facts will be added with the origin of the user performing the upload to the platform.

For managing origins, use the tool `act-origin` in `act-admin` package on pypi.

# Access mode
By default, all facts will have access-mode "RoleBased", which means that the user needs access to the organization specified when creating the facts.

The access mode can be explicit set with `--access-mode`, e.g. like this, to set all facts to Public access mode:

```
--access-mode Public
```

# Organization

All workers support the optional arguments `--organization` If they are not specified, facts will be added with the organization of the origin or the user performing the upload to the platform (if not set by the origin.


# Worker usage

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

# Proxy configuration

Workers will honor the `proxy-string` option on the command line when connecting to external APIs. However, if you need to
use the proxy to connect to the ACT platform (--act-baseurl), you will need to add the "--proxy-platform" switch:

```bash
echo -n www.mnemonic.no | act-vt --proxy-string <PROXY> --user-id <USER-ID> --act-baseurl <ACT-HOST> --proxy-platform
```

# Local development

Use pip to install in [local development mode](https://pip.pypa.io/en/stable/reference/pip_install/#editable-installs). act-workers (and act-api) uses namespacing, so it is not compatible with using `setup.py install` or `setup.py develop`.

In repository, run:

```bash
pip3 install --user -e .
```
# search
A worker to run graph queries is also included. A sample search config is inscluded in `etc/searc_jobs.ini`:

```bash
act-search-graph etc/search_jobs.ini
```

# act-feed

`act-feed` can be used to download feed bundles from a remote uri. Feed uri must have a file, manifest.json, that lists all bundle files that can be download by the feed worker:

```json
{
     "bundles": {
          "000bd93b8ce1fa2acfa448fa916083d76e64b008e336d6f54ad89f12f4232dcf.gz": 1636355543,
          "0598e898979bc851d58b440a3ea248fe64d9df4d2ab1665da3be73c6d13df411.gz": 1636681082,
          "0c03f87d142345a1bbea0867c145608e70ab2c0ea8282b5e06833f5f2b0f5f04.gz": 1636366321,
     },
     "updated": 1636699081
}
```

A local cache will be stored stored to keep track of the last bundle download, so bundles will not be downloaded multiple times.

You can either let act-feed download files to a local directory:

```bash
act-feed --feed-uri https://act.mnemonic.no/feed --dump-dir [path]
```

output all facts to stdout:

```bash
act-feed --feed-uri https://act.mnemonic.no/feed 
```

or upload facts directory to the platform

```bash
act-feed --feed-uri https://act.mnemonic.no/feed --act-baseurl [platform UR] --user-id [USERID]
```

# act-fact-chain-helper

The act-fact-chain-helper is a utility that can be used to add facts chains based on known start and end nodes. This can be usefull when adding
information from reports where do not have all the information availiable to you.

## example

We know from a report that the threat actor APT 1 uses the tool Mimikatz

```bash
$ act-fact-chain-helper --output-format str --start threatActor/apt1 --end tool/mimikatz --avoid mentions --include content
(incident/[placeholder[1194f1ba4ea8ded28250a0193327654e5ee305bce03741a3e6f183f03b5c6b35]]) -[attributedTo]-> (threatActor/apt1)
(event/[placeholder[1194f1ba4ea8ded28250a0193327654e5ee305bce03741a3e6f183f03b5c6b35]]) -[attributedTo]-> (incident/[placeholder[1194f1ba4ea8ded28250a0193327654e5ee305bce03741a3e6f183f03b5c6b35]])
(content/[placeholder[1194f1ba4ea8ded28250a0193327654e5ee305bce03741a3e6f183f03b5c6b35]]) -[observedIn]-> (event/[placeholder[1194f1ba4ea8ded28250a0193327654e5ee305bce03741a3e6f183f03b5c6b35]])
(content/[placeholder[1194f1ba4ea8ded28250a0193327654e5ee305bce03741a3e6f183f03b5c6b35]]) -[classifiedAs]-> (tool/mimikatz)
```

In this case we do need to hint at the tool that it should include the "content" object and avoid "mention" facts.

The source and destination is interchangeable. In the example above, the fact chain created by swapping the source and destination is identical.

by adding the ```--act-baseurl``` option, the data will be stored to the platform.

The tool works by finding the shortest path though the datamodel. The options --avoid and --include will modify the cost of traversing certain nodes or edges. This tool is considered experimental.l.

# add-ta-helper

You can use `add-ta-helper` to create facts, including placeholders, for typical scenarios where you have some
information of TA activity, but not all.

This worker should not be used if any of objects listed as placeholders below are known.

```bash
  --ta THREAT-ACTOR             Threat Actor Name (Required)
  --ta-located-in COUNTRY       Country where threat actor is located
  --campaign CAMPAIGN           Campaign
  --techniques TECHNIQUES       List of techniques (commaseparated).
                                Support technique IDs, e.g. T1002 and name
                                e.g "Valid Accounts"
  --tools TOOLS                 List of tools (commaseparated)
  --sectors SECTORS             List of Sectors (commaseparated)
  --target-countries COUNTRIES  Target Countries (commaseparated)
```

You can run the tool with the options above, and add `--output-format str` to se a suggested list of facts.
You can then add `--act-baseurl` and `--user-id` to add the facts to a platform instance.


You can add all options on a single command line, like this example:
```bash
act-ta-helper \
    --output-format str \
    --ta HAFNIUM \
    --sectors pharmaceuticals,education,defense,non-profit \
    --tools PsExec,Procdump,7-Zip,Nishang,PowerCat,WinRar,SIMPLESEESHARP,SPORTSBALL,ChinaChopper,ASPXSPY,Covenant \
    --target-countries "Denmark,United States of America" \
    --campaign "Operation Exchange Marauder" \
    --ta-located-in China \
    --techniques T1588,T1003,T1190,T1560,T1583,T1071,T1114,T1567,T1136,T1021
```

The following facts/placeholders will be created based on the options (placeholders are marked with [*]):

## `ta-located-in`

Use this if you know the threat actor name and country where TA is located, but organization is unknown.

```
threatActor -[attributedTo]-> organization[*] -[locatedIn]-> country
```

## `campaign`

Use this if you know the threat actor and campaign name, but incident is unknown.

```
threatActor -[attributedTo]-> incident[*] -[attributedTo]-> campaign
```

## `techniques`

Use this if you know the threat actor and technique, but event and incident is unknown.


```
technique <-[classifiedAs]- event[*] -[attributedTo]-> incident[*] -[attributedTo]-> threatActor

```

## `tools`

Use if tool and threat actor is known, but incident, content and event is unknown.

```
threatActor <-[attributedTod]- incident[*] <-[attributedTod]- event[*] <-[observedIn]- content[*] -[classifiedAs]-> tool
```

## `sectors`

Use this if threat actor and target sector is known, but organization and incident is unknown.

```
threatActor -[attributedTo]-> incident[*] -[targets]-> organization[*] -[memberOf]-> sector
```

## `target-countries`

Use this if threat actor and target country is known, but organization and incident is unknown.

```
threatActor -[attributedTo]-> incident[*] -[targets]-> organization[*] -[locatedIn]-> country
```
