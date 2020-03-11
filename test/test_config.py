""" test config """
import argparse
import os

import caep

INI_TEST_FILE = os.path.join(os.path.dirname(__file__), "data/config_testdata.ini")


def __argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser("test argparse", allow_abbrev=False)
    parser.add_argument('--number', type=int, default=1)
    parser.add_argument('--bool', action='store_true')
    parser.add_argument('--str-arg')

    return parser


def test_argparse_only():
    """ all arguments from command line, using default for number and bool """

    parser = __argparser()

    commandline = "--str-arg test".split()

    args = caep.handle_args(parser, "actworkers", "actworkers.ini", "test", opts=commandline)

    assert args.number == 1
    assert args.str_arg == "test"
    assert not args.bool


def test_argparse_ini():
    """ all arguments from ini file """
    parser = __argparser()

    commandline = "--config {}".format(INI_TEST_FILE).split()

    args = caep.handle_args(parser, "actworkers", "actworkers.ini", "test", opts=commandline)

    assert args.number == 3
    assert args.str_arg == "from ini"
    assert args.bool is True


def test_argparse_env():
    """ all arguments from env """
    parser = __argparser()

    env = {
        "STR_ARG": "from env",
        "NUMBER": 4,
        "BOOL": "yes"  # accepts both yes and true
    }

    for key, value in env.items():
        os.environ[key] = str(value)

    args = caep.handle_args(parser, "actworkers", "actworkers.ini", "test", opts=[])

    assert args.number == 4
    assert args.str_arg == "from env"
    assert args.bool is True

    # Remove from environment variables
    for key in env:
        del os.environ[key]


def test_argparse_env_ini():
    """
    --number from enviorment
    --bool from ini
    --str-arg from cmdline

    """
    parser = __argparser()

    env = {
        "NUMBER": 4,
    }

    for key, value in env.items():
        os.environ[key] = str(value)

    commandline = "--config {} --str-arg cmdline".format(INI_TEST_FILE).split()

    args = caep.handle_args(parser, "actworkers", "actworkers.ini", "test", opts=commandline)

    assert args.number == 4
    assert args.str_arg == "cmdline"
    assert args.bool is True

    # Remove from environment variables
    for key in env:
        del os.environ[key]
