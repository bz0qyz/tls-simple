import os
import sys
import argparse
import logging
from configparser import ConfigParser
from types import SimpleNamespace
from arguments import AllArguments, Argument, EnvDefault

LOG_FORMAT = {
    "std_format": logging.Formatter(
        f'%(asctime)s %(levelname)-8s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'),
    "debug_format": logging.Formatter(
        f'%(asctime)s %(levelname)-8s:%(message)s (%(filename)s: %(lineno)d)',
        datefmt='%Y-%m-%d %H:%M:%S')
    }
LOG_LEVEL = {
    "critical": {"level": logging.CRITICAL, "format": LOG_FORMAT["std_format"]},
    "error": {"level": logging.ERROR, "format": LOG_FORMAT["std_format"]},
    "warning": {"level": logging.WARNING, "format": LOG_FORMAT["std_format"]},
    "info": {"level": logging.INFO, "format": LOG_FORMAT["std_format"]},
    "debug": {"level": logging.DEBUG, "format": LOG_FORMAT["debug_format"]},
    }


class Config:
    """
    Primary application configuration class
    Provides:
    1. Argument Parsing
    2. Configuration File Parsing
    3. Logging Configuration
    """
    name = "tls-simple"
    description = "Simple TLS Certificate Generator"
    version = "0.1.0"

    def __init__(self):
        self.main = None
        args = Arguments(
            app_name=self.name,
            app_version=self.version,
            app_description=self.description
            )
        # create an object for each configuration section
        for arg in args.config.__dict__:
            setattr(self, arg, getattr(args.config, arg))
        self.action = args.action
        self.debug = True if self.main.log_level == "debug" else False
        self.logger = Logger(log_level=self.main.log_level).logger


class Arguments:
    ACTION = {
        "cert": {"description": "Create a self-signed certificate"},
        "ca-cert": {"description": "Create a self-signed CA and certificate"}
    }

    def __init__(self, app_name: str, app_version: str, app_description: str):
        self.parser = argparse.ArgumentParser(description=app_description, prog=f"{app_name} {app_version}")
        self.action = None
        self.config = None

        def boolify(value):
            if isinstance(value, bool):
                return value
            if value.lower() in ['true', 't', 'yes', 'y', '1']:
                return True
            if value.lower() in ['false', 'f', 'no', 'n', '0']:
                return False
            return value

        # Action argument
        the_help = []
        for key, info in self.ACTION.items():
            the_help.append(f"'{key}' = {info['description']}")
        self.parser.add_argument("action",
                            choices=self.ACTION.keys(), default='cert', metavar='cert',
                            help=f'Action to perform: {", ".join(the_help)}'
                            )

        # Load the arguments objects from arguments.py
        for section, section_def in AllArguments.items():
            if "arguments" not in section_def:
                continue
            # Set the argument group name and description
            desc = section_def["description"] if "description" in section_def else f"{section} options"
            # Add the argument group to the parser
            setattr(self, f"{section}_group", self.parser.add_argument_group(desc))
            # Add the arguments to the group
            for arg_name, arg_def in section_def["arguments"].items():
                arg = Argument(name=arg_name, section=section, arg_def=arg_def)
                arg.add_argument(parser=getattr(self, f"{section}_group"))

        # Parse the command line arguments
        self.args = self.parser.parse_args()

        # Read in the configuration file if it exists
        if not os.path.isfile(f"{self.args.main__config_file}"):
            if self.args.main__config_file:
                print(f"[WARNING] Configuration file {self.args.main__config_file} not found. Using command line arguments.")
        else:
            self.args.main__config_file = os.path.abspath(self.args.main__config_file)
            self.config = ConfigParser()
            self.config.read(self.args.main__config_file)

            for section in self.config.sections():
                for key, value in self.config[section].items():
                    full_key = f"{section}__{key}"
                    # Override the command line arguments if the argument is not it's default value
                    if hasattr(self.args, full_key):
                        if getattr(self.args, full_key) == AllArguments[section]["arguments"][key]["default"]:
                            setattr(self.args, full_key, boolify(value))
                    else:
                        # Add the argument to the args object
                        setattr(self.args, full_key, value)

        # if the log level is not valid, set it to 'info'
        if self.args.main__log_level not in LOG_LEVEL.keys():
            self.args.main__log_level = 'info'

        # Convert parsed arguments to a nested object
        result = SimpleNamespace()
        for key, value in vars(self.args).items():
            if key == "action":
                self.action = value
                continue
            section, name = key.split('__')
            if not hasattr(result, section):
                setattr(result, section, SimpleNamespace())
            setattr(getattr(result, section), name, value)

        self.config = result

    def __repr__(self):
        return self.config

class Logger:
    def __init__(self, log_level):
        if log_level not in LOG_LEVEL.keys():
            log_level = 'info'

        self.debug = True if log_level == 'debug' else False
        # create the logger
        self.logger = logging.getLogger()
        self.logger.setLevel(LOG_LEVEL[log_level]["level"])
        # initialize the console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(LOG_LEVEL[log_level]["format"])
        self.logger.addHandler(console_handler)

    def __repr__(self):
        return self.logger

