import os
import logging
import ipaddress
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.x509 import NameOID, CertificateBuilder, BasicConstraints, CertificateSigningRequestBuilder
from cryptography.x509 import Name, NameAttribute, SubjectAlternativeName


class SslOps:
    """
    Handles all cryptography operations
    - Create TLS Private Keys
    - Create self-signed TLS Certificates, CA Certificates, and CA-signed Certificates
    """
    curve_mapping = {
        "prime256v1": ec.SECP256R1(),
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1()
    }
    hash_mapping = {
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512()
    }

    def __init__(self, output_dir: str, app_name: str, app_version: str, force: bool = False, pass_files: bool = False):
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir
        self.app_name = app_name
        self.app_version = app_version
        self.force = force
        self.pass_files = pass_files
        self.name = None       # Created from the certificate's common name
        self.ca_key = None     # CA Key Placeholder
        self.ca_key_pw = None  # CA Key Password Placeholder 
        self.ca_cert = None    # CA Certificate Placeholder
        self.crt_key = None    # Private Key Placeholder
        self.crt_key_pw = None # Private Key Password Placeholder
        self.crt_cert = None   # Certificate Placeholder

        # clean the output directory if force is set
        if self.force and os.path.isdir(self.output_dir):
            self.logger.debug(f"Cleaning the output directory '{self.output_dir}'")
            for file in os.listdir(self.output_dir):
                file_path = os.path.join(self.output_dir, file)
                try:
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                except Exception as e:
                    self.logger.error(f"Error deleting file '{file_path}': {e}")

        # Create the output directory if it does not exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def __key_to_pem__(self, key: ec.EllipticCurvePrivateKey, password_bytes: bytes = None):
        """ Convert key object to PEM: str format """
        if not password_bytes:
            pem_opts = {"encryption_algorithm": serialization.NoEncryption()}
        else:
            pem_opts = {"encryption_algorithm": serialization.BestAvailableEncryption(password_bytes)}
        private_key_pem =  key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            **pem_opts
        )

        return private_key_pem

    def __parse_subject__(self, subject: str):
        """ Parse a Subject line and create a cryptography subject object """
        subject_attributes = []
        subject_parts = subject.strip('/').split('/')
        for part in subject_parts:
            key, value = part.split('=')
            if key == 'C':
                subject_attributes.append(NameAttribute(NameOID.COUNTRY_NAME, value))
            elif key == 'ST':
                subject_attributes.append(NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, value))
            elif key == 'L':
                subject_attributes.append(NameAttribute(NameOID.LOCALITY_NAME, value))
            elif key == 'O':
                subject_attributes.append(NameAttribute(NameOID.ORGANIZATION_NAME, value))
            elif key == 'OU':
                subject_attributes.append(NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value))
            elif key == 'CN':
                subject_attributes.append(NameAttribute(NameOID.COMMON_NAME, value))
                self.name = value
        return Name(subject_attributes)

    def __parse_san__(self, cert_san: str):
        """ Parse the SAN sring into a cryptography subjectAlternateName object """
        san_list = []
        san_parts = cert_san.strip().split(',')
        for part in san_parts:
            key, value = part.split(':', 1)
            if key == 'DNS':
                san_list.append(x509.DNSName(value))
            elif key == 'IP':
                san_list.append(x509.IPAddress(ipaddress.IPv4Address(value)))
            elif key == 'IPv6':
                san_list.append(x509.IPAddress(ipaddress.IPv6Address(value)))
        return san_list

    def __output_file__(self, filename: str):
        """
        Return the full path to the output file
        if the filename is not an absolute path, prepend the output directory
        else return the filename as is
        """

        if os.path.isabs(filename):
            return_filename = filename
        if os.sep in filename:
            return_filename = filename
        else:
            return_filename = os.path.join(self.output_dir, filename)

        if not self.force and os.path.exists(return_filename):
            raise FileExistsError(f"Output file '{return_filename}' already exists. Use --force to overwrite.")
            # self.logger.error(f"Output file '{return_filename}' already exists. Use --force to overwrite.")
            # return None

        return return_filename

    def __chmod_file__(self, file: str):
        # Set 0600 permissions on the file
        try:
            os.chmod(file, 0o600)
        except Exception as e:
            self.logger.warning(f"Error setting permissions on file '{file}': {e}")

    def create_ecc_key(self, filename: str, ecc_curve: str, password: str = None, key_type: str = "crt"):
        """ Create ECC Private Keys """
        # Define the output file for the private key
        output_file = self.__output_file__(filename=filename)
        # define the key reference
        key_ref = f"{key_type}_key"
        # Define the curve name for ECC
        if ecc_curve not in self.curve_mapping:
            self.logger.error(f"Invalid ECC curve '{ecc_curve}'")
            self.logger.info(f"Valid ECC curves: {', '.join(self.curve_mapping.keys())}")
            self.logger.info(f"Using default curve 'secp256r1'")
        curve_type = self.curve_mapping.get(ecc_curve, ec.SECP256R1())
        self.logger.debug(f"Creating a self-signed key with ECC curve '{ecc_curve}'")

        password_bytes = None
        if password:
            self.logger.debug(f"Setting a password on the private key: '{password}'")
            password_bytes = password.encode('utf-8')
            setattr(self, f"{key_ref}_pw", password_bytes)

        # Generate ECC private key
        # print(f"Setting the key to the object: self.{key_ref}")
        private_key = ec.generate_private_key(curve_type)
        setattr(self, key_ref, private_key)

        private_key = getattr(self, key_ref)

        # Save the private key to a PEM format string
        private_key_pem = self.__key_to_pem__(private_key, password_bytes)
        # Save the private key to a file
        with open(f"{output_file}", "w") as key_file:
            key_file.write(private_key_pem.decode())
        # Set permissions on the private key file
        self.__chmod_file__(f"{output_file}")
        # Save the key's password to a file
        if password and self.pass_files:
            # Save the private key to a file
            self.logger.debug(f"Saving the password to a file: '{output_file}.pw'")
            with open(f"{output_file}.pw", "w") as key_file:
                key_file.write(password)
            # Set permissions on the private key file
            self.__chmod_file__(f"{output_file}.pw")

        # Return the output file name
        return f"{output_file}"

    def create_cert(self, filename: str, cert_subject: str, cert_days: int, sig_algorithm: str, cert_san: str = None, cert_type: str = "crt"):
        """ Create TLS Certificates. Self-signed and CA-signed """
        # Define the output file for the certificate
        output_file = self.__output_file__(filename=filename)
        # define the cert reference
        cert_ref = f"{cert_type}_cert"
        # define the key by reference
        private_key = getattr(self, f"{cert_type}_key")
        if not private_key:
            self.logger.error(f"A Private key must be created before a certificate can be created.")
            return None
        # Create the public key from the private key
        public_key = private_key.public_key()
        # Define the signature algorithm
        sig_algorithm = self.hash_mapping.get(sig_algorithm, hashes.SHA256())
        # Create a subject for the certificate (can be customized)
        subject = self.__parse_subject__(cert_subject)
        # create the valid from and valid to dates
        now = datetime.utcnow().date()
        # Set the valid_from to the current date at 00:00:00
        valid_from = datetime.combine(now, datetime.min.time())
        valid_to = valid_from + timedelta(days=int(cert_days))

        # Parse the SAN string into an x509.SubjectAlternativeName list of SANs
        san_list = None
        if cert_san:
            san_list = self.__parse_san__(cert_san=cert_san)

        # Create a custom v3 extension: 'nsComment' to tag the certificate
        ns_comment_oid = x509.oid.ObjectIdentifier("2.16.840.1.113730.1.13")  # OID for nsComment
        ns_comment_value = f"Created By: {self.app_name} v{self.app_version}".encode('utf-8')
        ns_comment_extension = x509.UnrecognizedExtension(ns_comment_oid, ns_comment_value)

        

        # Generate the certificate
        if self.ca_key and self.ca_cert:
            self.logger.debug(f"Creating a self-signed certificate signed by the CA")
            # Generate a certificate signing request (CSR)
            builder = CertificateSigningRequestBuilder().subject_name(subject
                ).add_extension(BasicConstraints(ca=False, path_length=None), critical=True).add_extension(
                ns_comment_extension, critical=False)
            if san_list:
                builder = builder.add_extension(SubjectAlternativeName(san_list), critical=False)

            # Sign the CSR with your CA private key
            signed_csr = builder.sign(self.crt_key, sig_algorithm)
            cert_builder = x509.CertificateBuilder().subject_name(
                signed_csr.subject
            ).issuer_name(
                self.ca_cert.subject  # CA certificate's subject
            ).public_key(
                signed_csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                valid_from
            ).not_valid_after(
                valid_to
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            ).add_extension(
                ns_comment_extension, critical=False)

            if san_list:
                cert_builder = cert_builder.add_extension(
                    SubjectAlternativeName(san_list), critical=False)
            signed_cert = cert_builder.sign(private_key=self.ca_key, algorithm=sig_algorithm)
        else:
            self.logger.debug(f"Creating a self-signed certificate")
            builder = CertificateBuilder().subject_name(subject).issuer_name(subject).not_valid_before(
                valid_from).not_valid_after(valid_to).public_key(
                public_key).serial_number(x509.random_serial_number()).add_extension(
                ns_comment_extension, critical=False)
            # Mark the certificate as a CA if that is the type
            if cert_type == "ca":
                builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            if san_list:
                builder = builder.add_extension(
                    SubjectAlternativeName(san_list), critical=False)
            # Sign the certificate using the private key
            signed_cert = builder.sign(private_key, sig_algorithm)

        # Save the certificate to the object
        # print(f"Setting the certificate to the object: self.{cert_ref}")
        setattr(self, cert_ref, signed_cert)
        # Save the certificate to a PEM format string
        signed_cert_pem = signed_cert.public_bytes(serialization.Encoding.PEM)
        # Save the certificate to a file
        with open(f"{output_file}", "w") as cert_file:
            cert_file.write(signed_cert_pem.decode())

        # Return the output file name
        return f"{output_file}"


    def create_pfx(self, pfx_file: str, pfx_password: str):
        """ Generate a PFX (PKCS12) Container format file """
        output_file = self.__output_file__(filename=pfx_file)
        self.logger.debug(f"Creating a PFX file: '{output_file}' with password: '{pfx_password}'")
        # Convert password to bytes
        password_bytes = pfx_password.encode('utf-8')
        # Create the PFX file
        all_certs = {
            "key": self.crt_key,
            "cert": self.crt_cert,
            "cas": []
        }
        if self.ca_cert:
            all_certs["cas"].append(self.ca_cert)

        encryption = (
            serialization.PrivateFormat.PKCS12.encryption_builder().
            kdf_rounds(50000).
            key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).
            hmac_hash(hashes.SHA1()).build(password_bytes)
        )
        # encryption = serialization.BestAvailableEncryption(password_bytes)


        pfx = pkcs12.serialize_key_and_certificates(
            name=f"{self.name}".encode('utf-8'),  # Optional friendly name
            encryption_algorithm=encryption,
            **all_certs
        )

        # Write to file
        with open(f"{output_file}", "wb") as f:
            f.write(pfx)
        self.__chmod_file__(f"{output_file}")
        # Write password to a file
        if self.pass_files:
            self.logger.debug(f"Saving the password to a file: '{output_file}.pw'")
            with open(f"{output_file}.pw", "w") as f:
                f.write(pfx_password)
            self.__chmod_file__(f"{output_file}.pw")

        # Set permissions on the pfx key file
        try:
            os.chmod(output_file, 0o600)
        except Exception as e:
            self.logger.warning(f"Error setting permissions on file '{output_file}': {e}")

        return f"{output_file}"


