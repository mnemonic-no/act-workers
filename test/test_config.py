""" test config """
import argparse
import os

from act.workers.libs import config

INI_TEST_FILE = os.path.join(os.path.dirname(__file__), "data/config_testdata.ini")


def test_argparse_only():
    """ all arguments from command line, using default for number and bool """
    parser = argparse.ArgumentParser("test argparse")
    parser.add_argument('--number', type=int, default=1)
    parser.add_argument('--bool', action='store_true')
    parser.add_argument('--str-arg')

    commandline = "--str test".split()

    args = config.handle_args(parser, "actworkers", "actworkers.ini", "test", opts=commandline)

    assert args.number == 1
    assert args.str_arg == "test"
    assert not args.bool


def test_argparse_ini():
    """ all arguments from ini file """
    parser = argparse.ArgumentParser("test argparse")
    parser.add_argument('--number', type=int, default=1)
    parser.add_argument('--bool', action='store_true')
    parser.add_argument('--str-arg')

    commandline = "--config {}".format(INI_TEST_FILE).split()

    args = config.handle_args(parser, "actworkers", "actworkers.ini", "test", opts=commandline)

    assert args.number == 3
    assert args.str_arg == "from ini"
    assert args.bool is True


def test_argparse_env():
    """ all arguments from env """
    parser = argparse.ArgumentParser("test argparse")
    parser.add_argument('--number', type=int, default=1)
    parser.add_argument('--bool', action='store_true')
    parser.add_argument('--str-arg')

    env = {
        "STR_ARG": "from env",
        "NUMBER": 4,
        "BOOL": "yes"  # accepts both yes and true
    }

    for key, value in env.items():
        os.environ[key] = str(value)

    args = config.handle_args(parser, "actworkers", "actworkers.ini", "test", opts=[])

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
    parser = argparse.ArgumentParser("test argparse")
    parser.add_argument('--number', type=int, default=1)
    parser.add_argument('--bool', action='store_true')
    parser.add_argument('--str-arg')

    env = {
        "NUMBER": 4,
    }

    for key, value in env.items():
        os.environ[key] = str(value)

    commandline = "--config {} --str-arg cmdline".format(INI_TEST_FILE).split()

    args = config.handle_args(parser, "actworkers", "actworkers.ini", "test", opts=commandline)

    assert args.number == 4
    assert args.str_arg == "cmdline"
    assert args.bool is True

    # Remove from environment variables
    for key in env:
        del os.environ[key]
