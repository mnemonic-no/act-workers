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

* act-attack
* act-country-regions
* act-misp-feeds
* act-mnemonic-pdns
* act-scio
* act-shadowserver-asn
* act-vt
* act-uploader

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
