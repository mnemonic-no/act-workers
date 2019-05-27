#!/usr/bin/env python

"""

config module, supports loading config from ini, environment and arguments

The configuration presedence are (from lowest to highest):
    1. argparse default
    3. ini file
    3. environment variable
    4. command line argument

# Config

Arguments are parsed in two phases. First, it will look for the argument --config argument
which can be used to specify an alternative location for the ini file. If not --config argument
is given it will look for an ini file in the following locations:

    /etc/<CONFIG_FILE_NAME>
    ~/.config/<CONFIG_ID>/<CONFIG_FILE_NAME> (or directory specified by XDG_CONFIG_HOME)

The ini file can contain a "[DEFAULT]" section that will be used for all configurations.
In addition it can have a section that corresponds with <SECTION_NAME> that for
specific cofiguration, that will over overide config from DEFAULT

# Environment variables

The configuration step will also look for environment variables in uppercase and
with "-" replaced with "_". For the example below it will lookup the following environment
variables:

    - $NUMBER
    - $BOOL
    - $STR_ARG

Example:

>>> parser = argparse.ArgumentParser("test argparse")
>>> parser.add_argument('--number', type=int, default=1)
>>> parser.add_argument('--bool', action='store_true')
>>> parser.add_argument('--str-arg')
>>> args = config.handle_args(parser, <CONFIG_ID>, <CONFIG_FILE_NAME>, <SECTION_NAME>)

"""

import argparse
import configparser
import os
from functools import partialmethod
from typing import Any, Dict, List, Optional, Text, Tuple

# Monkeypatch ArgumentParser to not allow abbrevations as those will make it
# hard to mix and match options on commandline, env and ini files
argparse.ArgumentParser.__init__ = partialmethod(argparse.ArgumentParser.__init__, allow_abbrev=False)  # type: ignore


class SectionNotFound(Exception):
    """Config file not found"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


class NotSupported(Exception):
    """Option not supported"""

    def __init__(self, *args: Any) -> None:
        Exception.__init__(self, *args)


def get_xdg_dir(xdg_id: Text, env_name: Text, default: Text, create: bool = False) -> Text:
    """
    Get xdg dir.

    https://specifications.freedesktop.org/basedir-spec/basedir-spec-0.6.html

    Honors $XDG_*_HOME, but fallbacks to defaults

Args:
    xdg_id [str]: directory under directory that will be used
    env_name [str]: XDG environment variable, e.g. XDG_CACHE_HOME
    env_name [str]: default directory in home directory, e.g. .cache
    create [bool]: create directory if not exists

Return path to cache_directory
    """

    home = os.environ["HOME"]

    xdg_home = os.environ.get(env_name, os.path.join(home, default))
    xdg_dir = os.path.join(xdg_home, xdg_id)

    if create and not os.path.isdir(xdg_dir):
        os.makedirs(xdg_dir)

    return xdg_dir


def get_config_dir(config_id: Text, create: bool = False) -> Text:
    """
    Get config dir.

    Honors $XDG_CONFIG_HOME, but fallbacks to ".config"

    See get_xdg_dir for details
    """

    return get_xdg_dir(config_id, "XDG_CONFIG_HOME", ".config", create)


def find_default_ini(ini_id: Text = "actworkers",
                     ini_filename: Text = "actworkers.ini") -> Optional[Text]:
    """
    Look for default ini files in /etc and ~/.config
    """

    # Order to search for confiuration files
    locations: List[Text] = [
        os.path.join(get_config_dir(ini_id), ini_filename),
        "/etc/{}".format(ini_filename)
    ]

    ini_files: List[Text] = [loc for loc in locations if os.path.isfile(loc)]

    if not ini_files:
        return None

    with open(ini_files[0]) as f:
        return f.read()


def load_ini(config_id: Text,
             config_name: Text,
             opts: Optional[List] = None) -> Tuple[Optional[configparser.ConfigParser], List]:
    """
    return config, remainder_argv
    """

    early_parser = argparse.ArgumentParser(description="configfile parser", add_help=False)
    early_parser.add_argument('--config', dest='config',
                              type=argparse.FileType('r', encoding='UTF-8'),
                              default=None,
                              help='change default configuration location')

    args, remainder_argv = early_parser.parse_known_args(opts)

    config = args.config

    if config:
        config = config.read()

    # No config file specified on command line, attempt to find
    # in default locations
    else:
        config = find_default_ini(config_id, config_name)

    if config:
        cp = configparser.ConfigParser()
        cp.read_string(config)
        return cp, remainder_argv

    return None, remainder_argv


def get_env(key: Text) -> Dict:
    """
    Get environment variable based on key
    (uppercase and replace "-" with "_")
    """
    env_key = key.replace("-", "_").upper()

    if env_key in os.environ:
        return {key: os.environ[env_key]}
    return {}


def get_default(action: argparse.Action, section: Dict, key: Text) -> Any:
    """
    Find default value for an option. This will only be used if an
    argument is not specified at the command line. The defaults will
    be found in this order and continue until a value is found:
        1. environment variable
        2. ini file
        3. argparse default

    This will only be used if the argument is not specified at the
    command line.
    """
    default = action.default
    env = get_env(key)

    # environment has higher presedence than config section
    if key in env:
        default = env[key]
    elif key in section:
        default = section[key]

    # if not env or section, keep default from argparse

    # parse true/yes as True and false/no as False for
    # action="store_true" and action="store_false"
    if action.const in (True, False) and isinstance(default, str):
        if default.lower() in ("true", "yes"):
            default = True
        elif default.lower() in ("false", "no"):
            default = False

    if action.nargs in (argparse.ZERO_OR_MORE, argparse.ONE_OR_MORE):
        default = default.split()

    # If argument type is set and default is not None, enforce type
    # Eg, for this argument specification
    # parser.add_argument('--int-arg', type=int)
    # --int-arg 2
    # will give you int(2)
    # If --int-arg is omitted, it will use None
    if action.type is not None and default is not None:
        default = action.type(default)

    return default


def handle_args(parser: argparse.ArgumentParser,
                config_id: Text,
                config_name: Text,
                section_name: Text,
                opts: Optional[List] = None) -> argparse.Namespace:
    """
    parses and sets up the command line argument system above
    with config file parsing.
    """

    cp, remainder_argv = load_ini(config_id, config_name, opts=opts)

    if cp:
        # Add (empty) section. In this way we can still access
        # the DEFAULT section
        if not cp.has_section(section_name):
            cp.add_section(section_name)
        config = dict(cp[section_name])
    else:
        config = {}

    # Loop over parser groups / actions
    # Unfortunately we can only do this in protected members..
    # pylint: disable=protected-access
    for g in parser._action_groups:
        for action in g._actions:
            if action.required:
                raise NotSupported('"required" argument is not supported (found in option {}). '.format("".join(action.option_strings)) +
                                   "Set to false and test after it has been parsed by handle_args()")
            for option_string in action.option_strings:
                if option_string.startswith('--'):
                    key=option_string[2:]
                    action.default=get_default(action, config, key)

    return parser.parse_args(remainder_argv)
