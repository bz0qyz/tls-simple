# tls-simple
Simple TLS Certificate Generator

## Build
Releases are built using PyInstaller. See the [Releases](/releases) page for the latest release.

To build the application from source, you can use the `build.sh` script if you are using a bash shell.
```shell
./build.sh
```


## Usage
The application can be configured using:
1. Command line arguments
2. Environment variables
3. An INI configuration file

```shell
usage: tls-simple 0.1.0 [-h] [-l info] [-c /path/to/config.ini] [-o /Users/russcook/gitlocal/bz0qyz/tls-simple/output] [-f true|false] [--password-files true|false] [-pfx true|false] [-kf key.pem] [-cf cert.pem]
                        [-pf cert.pfx] [-xp <password>] [-kp <password>] [-cd 365] [-csubj /CN=localhost] [-ce admin@domain.com] [--cert-san DNS:localhost,DNS:localhost.localdomain,IP:127.0.0.1,IPv6:fe80::1]
                        [--cert-sig-algo sha512] [--crt-ecc-curve prime256v1] [-cakf ca_key.pem] [-cacf ca_cert.pem] [-cakp <password>] [-cad 365] [-casubj /CN=Example CA] [-cae admin@domain.com]
                        [--ca-sig-algo sha512] [--ca-ecc-curve prime256v1]
                        cert
```
### Configuration File (INI)
See the `tls-simple.ini` file for an example configuration file.   
Usage: `tls-simple -c tls-simple.ini cert|ca-cert`
#### Sections:
1. `main`: Global settings
2. `cert`: Certificate settings
3. `ca`: CA Certificate settings

### Command line Arguments
Each argument has an associated environment variable and INI configuration file setting. 
The command line argument takes precedence over the environment variable, which takes precedence over the INI configuration file setting.
#### positional arguments:
```shell
  cert : Action to perform: 'cert' = Create a self-signed certificate, 'ca-cert' = Create a self-signed CA and certificate
```
#### Global options:
```shell
  -h, --help            show this help message and exit
  -l info, --log-level info
                        Log level: info, debug, warning, error, critical. ENV: SS_LOG_LEVEL ini: main.log_level (default: info)
  -c /path/to/config.ini, --config-file /path/to/config.ini
                        Use an unattended configuration file. ENV: SS_CONFIG_FILE ini: main.config_file
  -o /Users/russcook/gitlocal/bz0qyz/tls-simple/output, --output-dir /Users/russcook/gitlocal/bz0qyz/tls-simple/output
                        Output directory for generated files. (Default: '<CWD>/output') ENV: SS_OUTPUT_DIR ini: main.output_dir (default: /Users/russcook/gitlocal/bz0qyz/tls-simple/output)
  -f true|false, --force true|false
                        Force overwrite of existing files. ENV: SS_FORCE ini: main.force (default: False)
  --password-files true|false
                        Create password files for private keys and PFX files. ENV: SS_PASSWORD_FILES ini: main.password_files (default: False)
```
#### Certificate Options:
```shell
  -pfx true|false, --cretate-pfx true|false
                        Create a Personal Information Exchange (.pfx) file. ENV: SS_CREATE_PFX ini: cert.create_pfx (default: False)
  -kf key.pem, --key-filename key.pem
                        Private Key file name. ENV: SS_KEY_FILENAME ini: cert.key_filename (default: key.pem)
  -cf cert.pem, --cert-filename cert.pem
                        Certificate file name. ENV: SS_CRT_FILENAME ini: cert.cert_filename (default: cert.pem)
  -pf cert.pfx, --pfx-filename cert.pfx
                        PFX file name. ENV: SS_PFX_FILENAME ini: cert.pfx_filename (default: cert.pfx)
  -xp <password>, --pfx-password <password>
                        Password to encrypt the pfx file. Required if --create-pfx is set. ENV: SS_PFX_PASSWORD ini: cert.pfx_password
  -kp <password>, --key-password <password>
                        Password to encrypt the private key. If unset, key will be unencrypted. ENV: SS_KEY_PASSWORD ini: cert.key_password
  -cd 365, --cert-days 365
                        Number of days the certificate is valid. ENV: SS_CERT_DAYS ini: cert.days (default: 365)
  -csubj /CN=localhost, --cert-subject /CN=localhost
                        Certificate Subject string. ENV: SS_CERT_SUBJECT ini: cert.subject (default: /CN=localhost)
  -ce admin@domain.com, --cert-email admin@domain.com
                        Email address for the certificate. ENV: SS_CERT_EMAIL ini: cert.email
  --cert-san DNS:localhost,DNS:localhost.localdomain,IP:127.0.0.1,IPv6:fe80::1
                        Certificate Subject Alternative Name (SAN). Hostname or IP Address. ini: cert.san (default: DNS:localhost,DNS:localhost.localdomain,IP:127.0.0.1,IPv6:fe80::1)
  --cert-sig-algo sha512
                        Certificate Signature Algorithm. ENV: SS_CERT_SIG_ALGO ini: cert.sig_algorithm (default: sha512)
  --crt-ecc-curve prime256v1
                        ECC Curve name for the certificate. ENV: SS_CERT_ECC_CURVE ini: cert.ecc_curve (default: prime256v1)
```
### CA Certificate Options:
```shell
  -cakf ca_key.pem, --ca-key-filename ca_key.pem
                        CA Private Key file name. ENV: SS_CA_KEY_FILENAME ini: ca.key_filename (default: ca_key.pem)
  -cacf ca_cert.pem, --ca-crt-filename ca_cert.pem
                        CA Certificate file name. ENV: SS_CA_CRT_FILENAME ini: ca.cert_filename (default: ca_cert.pem)
  -cakp <password>, --ca-key-password <password>
                        Password to encrypt the CA private key. If unset, key will be unencrypted. ENV: SS_CA_KEY_PASSWORD ini: ca.key_password
  -cad 365, --ca-days 365
                        Number of days the CA certificate is valid. ENV: SS_CA_DAYS ini: ca.days (default: 365)
  -casubj /CN=Example CA, --ca-cert-subject /CN=Example CA
                        Certificate Subject string. ENV: SS_CA_CERT_SUBJECT ini: ca.subject (default: /CN=Example CA)
  -cae admin@domain.com, --ca-email admin@domain.com
                        Email address for the certificate. ENV: SS_CERT_EMAIL ini: ca.email
  --ca-sig-algo sha512  Certificate Signature Algorithm. ENV: SS_CA_SIG_ALGO ini: ca.sig_algorithm (default: sha512)
  --ca-ecc-curve prime256v1
                        ECC Curve name for the CA certificate. ENV: SS_CA_ECC_CURVE ini: ca.ecc_curve (default: prime256v1)
```
