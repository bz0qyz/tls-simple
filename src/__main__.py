import os
from config import Config
from sslops import SslOps

config = Config()
logger = config.logger
final_output = []

ssl_ops = SslOps(
    output_dir=config.main.output_dir,
    app_name=config.name,
    app_version=config.version,
    force=config.main.force,
    pass_files=config.main.password_files
)


# Create a CA key and certificate if requested
if config.action == "ca-cert":
    logger.info("Creating a self-signed CA certificate")
    # Create a self-signed CA
    ca_private_key_file = ssl_ops.create_ecc_key(
        filename=config.ca.key_filename,
        ecc_curve=config.ca.ecc_curve,
        password=config.cert.key_password,
        key_type="ca"
    )
    final_output.append(f"CA Private Key file: '{ca_private_key_file}'")
    if config.main.password_files:
        final_output.append(f"CA Private Key password file: '{ca_private_key_file}.pw'")

    ca_cert_file = ssl_ops.create_cert(
        filename=config.ca.cert_filename,
        cert_subject=config.ca.subject,
        cert_email=config.ca.email,
        cert_days=config.ca.days,
        sig_algorithm=config.ca.sig_algorithm,
        cert_type="ca"
    )
    final_output.append(f"CA Certificate file: '{ca_cert_file}'")


# Create a self-signed certificate
logger.info("Creating a self-signed certificate")
crt_private_key_file = ssl_ops.create_ecc_key(
    filename=config.cert.key_filename,
    ecc_curve=config.cert.ecc_curve,
    password=config.cert.key_password
)
final_output.append(f"Private Key file: '{crt_private_key_file}'")
if config.main.password_files:
    final_output.append(f"Private Key password file: '{crt_private_key_file}.pw'")


crt_cert_file = ssl_ops.create_cert(
    filename=config.cert.cert_filename,
    cert_subject=config.cert.subject,
    cert_email=config.cert.email,
    cert_days=config.cert.days,
    sig_algorithm=config.cert.sig_algorithm,
    cert_san=config.cert.san
)
final_output.append(f"Certificate file: '{crt_cert_file}'")

if config.cert.create_pfx:
    pfx_file = ssl_ops.create_pfx(
        pfx_file=config.cert.pfx_filename,
        pfx_password=config.cert.pfx_password
    )

    final_output.append(f"PFX Container file: '{pfx_file}'")
    if config.main.password_files:
        final_output.append(f"PFX Container password file: '{pfx_file}.pw'")

# Write Final Output
try:
    size = os.get_terminal_size()
except OSError:
    size = os.terminal_size((80, 24))

print("-" * size.columns)
print("\n## Certificate Files:")
print("-" * size.columns)
for line in final_output:
    print(f" * {line}")
print("-" * size.columns)
