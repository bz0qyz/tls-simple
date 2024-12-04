import os
import sys
import argparse

# Get the current working directory
cwd=os.getcwd()

# A Dictionary that configures all available arguments/configuration
AllArguments = {
    "main": {
      "description": "Global options",
      "arguments": {
        "log_level": {
            "args": ['-l', '--log-level'],
            "type": str,
            "default": "info",
            "metavar": "info",
            "envvar": "SS_LOG_LEVEL",
            "help": "Log level: info, debug, warning, error, critical."
        },
        "config_file": {
            "args": ['-c', '--config-file'],
            "type": str,
            "default": None,
            "metavar": "/path/to/config.ini",
            "envvar": "SS_CONFIG_FILE",
            "help": "Use an unattended configuration file."
        },
        "output_dir": {
            "args": ['-o', '--output-dir'],
            "type": str,
            "default": f"{cwd}/output",
            "envvar": "SS_OUTPUT_DIR",
            "help": "Output directory for generated files. (Default: '<CWD>/output')"
        },
        "force": {
            "args": ['-f', '--force'],
            "type": bool,
            "default": False,
            "metavar": "true|false",
            "envvar": "SS_FORCE",
            "help": "Force overwrite of existing files."
        },
        "password_files": {
            "args": ['--password-files'],
            "type": bool,
            "default": False,
            "metavar": "true|false",
            "envvar": "SS_PASSWORD_FILES",
            "help": "Create password files for private keys and PFX files."
        }
    }
  },
    "cert": {
      "description": "Certificate Options",
      "arguments": {
        "create_pfx": {
          "args": ['-pfx', '--cretate-pfx'],
          "type": bool,
          "default": False,
          "metavar": "true|false",
          "envvar": "SS_CREATE_PFX",
          "help": "Create a Personal Information Exchange (.pfx) file."
        },
        "key_filename": {
            "args": ['-kf', '--key-filename'],
            "type": str,
            "default": 'key.pem',
            "envvar": "SS_KEY_FILENAME",
            "help": "Private Key file name."
        },
        "cert_filename": {
            "args": ['-cf', '--cert-filename'],
            "type": str,
            "default": 'cert.pem',
            "envvar": "SS_CRT_FILENAME",
            "help": "Certificate file name."
        },
        "pfx_filename": {
            "args": ['-pf', '--pfx-filename'],
            "type": str,
            "default": 'cert.pfx',
            "envvar": "SS_PFX_FILENAME",
            "help": "PFX file name."
        },
        "pfx_password": {
            "args": ['-xp', '--pfx-password'],
            "type": str,
            "default": None,
            "metavar": "<password>",
            "envvar": "SS_PFX_PASSWORD",
            "help": "Password to encrypt the pfx file. Required if --create-pfx is set."
        },
        "key_password": {
            "args": ['-kp', '--key-password'],
            "type": str,
            "default": None,
            "metavar": "<password>",
            "envvar": "SS_KEY_PASSWORD",
            "help": "Password to encrypt the private key. If unset, key will be unencrypted."
        },
        "days": {
            "args": ['-cd', '--cert-days'],
            "type": int,
            "default": 365,
            "envvar": "SS_CERT_DAYS",
            "help": "Number of days the certificate is valid."
        },
        "subject": {
            "args": ['-csubj', '--cert-subject'],
            "type": str,
            "default": "/CN=localhost",
            "envvar": "SS_CERT_SUBJECT",
            "help": "Certificate Subject string."
        },
        "email": {
            "args": ['-ce', '--cert-email'],
            "type": str,
            "default": None,
            "metavar": "admin@domain.com",
            "envvar": "SS_CERT_EMAIL",
            "help": "Email address for the certificate."
        },
        "san": {
            "args": ['--cert-san'],
            "type": str,
            "default": "DNS:localhost,DNS:localhost.localdomain,IP:127.0.0.1,IPv6:fe80::1",
            "help": "Certificate Subject Alternative Name (SAN). Hostname or IP Address."
        },
        "sig_algorithm": {
            "args": ['--cert-sig-algo'],
            "type": str,
            "default": "sha512",
            "envvar": "SS_CERT_SIG_ALGO",
            "help": "Certificate Signature Algorithm."
        },
        "ecc_curve": {
            "args": ['--crt-ecc-curve'],
            "type": str,
            "default": "prime256v1",
            "envvar": "SS_CERT_ECC_CURVE",
            "help": "ECC Curve name for the certificate."
        }
      }
  },
    "ca": {
      "description": "CA Certificate Options",
      "arguments": {
        "key_filename": {
            "args": ['-cakf', '--ca-key-filename'],
            "type": str,
            "default": 'ca_key.pem',
            "envvar": "SS_CA_KEY_FILENAME",
            "help": "CA Private Key file name."
        },
        "cert_filename": {
            "args": ['-cacf', '--ca-crt-filename'],
            "type": str,
            "default": 'ca_cert.pem',
            "envvar": "SS_CA_CRT_FILENAME",
            "help": "CA Certificate file name."
        },
        "key_password": {
            "args": ['-cakp', '--ca-key-password'],
            "type": str,
            "default": None,
            "metavar": "<password>",
            "envvar": "SS_CA_KEY_PASSWORD",
            "help": "Password to encrypt the CA private key. If unset, key will be unencrypted."
        },
        "days": {
            "args": ['-cad', '--ca-days'],
            "type": int,
            "default": 365,
            "envvar": "SS_CA_DAYS",
            "help": "Number of days the CA certificate is valid."
        },
        "subject": {
            "args": ['-casubj', '--ca-cert-subject'],
            "type": str,
            "default": "/CN=Example CA",
            "envvar": "SS_CA_CERT_SUBJECT",
            "help": "Certificate Subject string."
        },
        "email": {
            "args": ['-cae', '--ca-email'],
            "type": str,
            "default": None,
            "metavar": "admin@domain.com",
            "envvar": "SS_CERT_EMAIL",
            "help": "Email address for the certificate."
        },
        "sig_algorithm": {
            "args": ['--ca-sig-algo'],
            "type": str,
            "default": "sha512",
            "envvar": "SS_CA_SIG_ALGO",
            "help": "Certificate Signature Algorithm."
        },
        "ecc_curve": {
            "args": ['--ca-ecc-curve'],
            "type": str,
            "default": "prime256v1",
            "envvar": "SS_CA_ECC_CURVE",
            "help": "ECC Curve name for the CA certificate."
        }
      }
    }
}

class Argument:
    def __init__(self, name: str, section: str, arg_def: dict):
        self.name = name
        self.section = section
        self.args = []
        self.required = False
        self.default = None
        self.metavar = None
        self.envvar = None
        self.choices = None
        self.help = ""
        self.action = None

        for key, value in arg_def.items():
            if hasattr(self, key):
                setattr(self, key, value)

        if self.envvar:
            self.help += f" ENV: {self.envvar}"
            self.action = EnvDefault

        # Add the ini file option
        self.help += f" ini: {self.section}.{self.name}"

        # Create the destination name
        self.dest = f"{self.section}__{self.name}"

        # Append the default value to the help text
        if hasattr(self, "default") and self.default is not None:
            self.help += f" (default: {self.default})"

        # Set the metavar to the default value if not set
        if not self.metavar and self.default is not None:
            self.metavar = self.default

    def add_argument(self, parser):
        arg_opts = {}
        if self.envvar:
            arg_opts["envvar"] = self.envvar
        if self.choices:
            arg_opts["choices"] = self.choices

        parser.add_argument(*self.args, required=self.required,
                            help=self.help, default=self.default, metavar=self.metavar,
                            action=self.action, dest=self.dest, **arg_opts)


class EnvDefault(argparse.Action):
    """ Argparse Action that uses ENV Vars for default values """

    def boolify(self, value):
        if isinstance(value, bool):
            return value
        if value.lower() in ['true', 't', 'yes', 'y', '1']:
            return True
        if value.lower() in ['false', 'f', 'no', 'n', '0']:
            return False
        return value

    def __init__(self, envvar, required=False, default=None, **kwargs):
        if envvar and envvar in os.environ:
            default = self.boolify(os.environ[envvar])
            required = False

        super().__init__(default=default,
                         required=required,
                         **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, self.boolify(values))
