# Copyright: 2018, CCX Technologies

import os
import typing
import ipaddress
import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def create_key_file(filename: str, passcode: str = ''):
    """Create a key file suitable for use with ssl.

    Returns:
        A random key which can be used by the ssl tools in this module.
    """

    key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
    )

    if passcode:
        encryption_algorithm = serialization.BestAvailableEncryption(
                passcode.encode()
        )
    else:
        encryption_algorithm = \
                serialization.NoEncryption()  # type: ignore[assignment]

    key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption_algorithm
    )

    with open(filename, "wb") as fo:
        fo.write(key_bytes)

    os.chmod(filename, 0o600)


def create_csr(
        filename: str,
        private_key_file: str,
        passcode: str,
        common_name: str,
        dns_names: typing.List = None,
        ip_addresses: typing.List = None,
        country: str = "CA",
        province: str = "Ontario",
        locality: str = "Ottawa",
        organization: str = "CCX Technologies Inc.",
):
    """Create a x.509 Certificate Signing Request (CSR).

    Can be sent to another server which can create an Intermediate Certificate.

    Args:
        filename (str): name of the certificate file to create
        private_key_file (str): private key file created with create_key_file
        passcode (str): passcode associated with the private_key
        common_name (str): common name for the resulting certificate
        dns_names (list): optional, a list of DNS Names to associate
            with this certificate
        ip_addresses (list): optional, a list of IP Addresses to associate
            with this certificate
        country (str): optional, name of the country the Certificate is for
        province (str): optional, name of the province the Certificate is for
        locality (str): optional, name of the locality the Certificate is for
        organization (str): optional, name of the organization
            the Certificate is for
    """

    with open(private_key_file, 'rb') as fi:
        private_key = fi.read()

    key = serialization.load_pem_private_key(
            data=private_key,
            password=passcode.encode(),
            backend=default_backend()
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(
                    [
                            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                            x509.NameAttribute(
                                    NameOID.STATE_OR_PROVINCE_NAME, province
                            ),
                            x509.NameAttribute(
                                    NameOID.LOCALITY_NAME, locality
                            ),
                            x509.NameAttribute(
                                    NameOID.ORGANIZATION_NAME, organization
                            ),
                            x509.NameAttribute(
                                    NameOID.COMMON_NAME, common_name
                            ),
                    ]
            )
    )

    if dns_names:
        _dns_names = [x509.DNSName(n) for n in dns_names]
        csr = csr.add_extension(
                x509.SubjectAlternativeName(_dns_names), critical=False
        )

    if ip_addresses:
        _ip_addresses = [
            x509.IPAddress(ipaddress.IPv4Address(str(a))) for a in ip_addresses
        ]
        csr = csr.add_extension(
                x509.SubjectAlternativeName(_ip_addresses), critical=False
        )

    csr_signed = csr.sign(key, hashes.SHA512(), default_backend())

    with open(filename, 'wb') as fo:
        fo.write(csr_signed.public_bytes(encoding=serialization.Encoding.PEM))


def create_certificate_from_csr(
        filename: str,
        csr_file: str,
        ca_certificate_file: str,
        ca_private_key_file: str,
        ca_passcode: str,
        cert_length_days: int = 367
):
    """Create a x.509 Certificate from a Certificate Signing Request (CSR).

    Args:
        filename (str): name of the certificate file to create
        csr_file (str): name of the CSR file to use
        ca_private_key_file (str): key file for the Certificate Authority
        ca_certificate_file (str): cert file for the Certificate Authority
        ca_passcode (str): passcode associated with the private_key
        cert_length_days (int): optional, valid length of certificate
    """

    with open(csr_file, 'rb') as fi:
        csr = fi.read()

    with open(ca_private_key_file, 'rb') as fi:
        ca_private_key = fi.read()

    with open(ca_certificate_file, 'rb') as fi:
        ca_certificate = fi.read()

    _csr = x509.load_pem_x509_csr(csr, default_backend())

    if not _csr.is_signature_valid:
        raise RuntimeError('CSR has invalid signature.')

    private_key = serialization.load_pem_private_key(
            data=ca_private_key,
            password=ca_passcode.encode(),
            backend=default_backend()
    )

    ca_cert = x509.load_pem_x509_certificate(ca_certificate, default_backend())

    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.issuer_name(ca_cert.subject)

    valid_from = datetime.datetime.utcnow()
    valid_to = valid_from + datetime.timedelta(days=cert_length_days)

    builder = builder.not_valid_before(valid_from)
    builder = builder.not_valid_after(valid_to)
    builder = builder.subject_name(_csr.subject)
    builder = builder.public_key(_csr.public_key())

    for extension in _csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)

    builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(_csr.public_key()),
            critical=False
    )

    issuer_ski = ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
    )

    builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                    key_identifier=issuer_ski.value.digest,
                    authority_cert_issuer=None,
                    authority_cert_serial_number=None
            ),
            critical=False
    )

    client_cert = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA512(),
            backend=default_backend()
    )

    with open(filename, 'wb') as fo:
        fo.write(client_cert.public_bytes(encoding=serialization.Encoding.PEM))


def create_certificate_from_ca(
        filename: str,
        private_key_file: str,
        passcode_file: str,
        ca_certificate_file: str,
        common_name: bytes,
        dns_names: typing.List = None,
        ip_addresses: typing.List = None,
        country: str = "CA",
        province: str = "Ontario",
        locality: str = "Ottawa",
        organization: str = "CCX Technologies Inc.",
        cert_length_days: int = 367
):
    """Create a x.509 Certificate.

    Args:
        filename (str): name of the certificate file to create
        private_key_file (str): private key file created with create_key_file
        passcode_file (str): passcode file associated with the private_key
        ca_certificate_file (str): Certificate Authority's Certificate
        common_name (bytes): common name for the resulting certificate
        dns_names (list): optional, a list of DNS Names to associate
            with this certificate
        ip_addresses (list): optional, a list of IP Addresses to associate
            with this certificate
        country (str): optional, name of the country the Certificate is for
        province (str): optional, name of the province the Certificate is for
        locality (str): optional, name of the locality the Certificate is for
        organization (str): optional, name of the organization
            the Certificate is for
        cert_length_days (int): optional, valid length of certificate
    """

    with open(private_key_file, 'rb') as fi:
        _private_key = fi.read()

    with open(passcode_file, 'rb') as fi:
        passcode = fi.read().strip()

    with open(ca_certificate_file, 'rb') as fi:
        ca_certificate = fi.read()

    private_key = serialization.load_pem_private_key(
            data=_private_key, password=passcode, backend=default_backend()
    )

    _ca_cert = x509.load_pem_x509_certificate(
            ca_certificate, default_backend()
    )

    builder = x509.CertificateBuilder()

    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.issuer_name(_ca_cert.subject)

    valid_from = datetime.datetime.utcnow()
    valid_to = valid_from + datetime.timedelta(days=cert_length_days)

    builder = builder.not_valid_before(valid_from)
    builder = builder.not_valid_after(valid_to)

    builder = builder.subject_name(
            x509.Name(
                    [
                            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                            x509.NameAttribute(
                                    NameOID.STATE_OR_PROVINCE_NAME, province
                            ),
                            x509.NameAttribute(
                                    NameOID.LOCALITY_NAME, locality
                            ),
                            x509.NameAttribute(
                                    NameOID.ORGANIZATION_NAME, organization
                            ),
                            x509.NameAttribute(
                                    NameOID.COMMON_NAME, common_name
                            ),
                    ]
            )
    )

    builder = builder.public_key(private_key.public_key())

    if dns_names:
        _dns_names = [x509.DNSName(n) for n in dns_names]
        builder = builder.add_extension(
                x509.SubjectAlternativeName(_dns_names), critical=False
        )

    if ip_addresses:
        _ip_addresses = [
            x509.IPAddress(ipaddress.IPv4Address(str(a))) for a in ip_addresses
        ]
        builder = builder.add_extension(
                x509.SubjectAlternativeName(_ip_addresses), critical=False
        )

    builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                    private_key.public_key()
            ),
            critical=False
    )

    issuer_ski = _ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
    )

    builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                    key_identifier=issuer_ski.value.digest,
                    authority_cert_issuer=None,
                    authority_cert_serial_number=None
            ),
            critical=False
    )

    client_cert = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA512(),
            backend=default_backend()
    )

    with open(filename, 'wb') as fo:
        fo.write(client_cert.public_bytes(encoding=serialization.Encoding.PEM))


def create_self_signed_certificate(
        filename: str,
        private_key_file: str,
        passcode: str,
        common_name: str,
        dns_names: typing.List = None,
        ip_addresses: typing.List = None,
        cert_length_days: int = 367
):
    """Create a x.509 Certificate.

    Args:
        filename (str): name of the certificate file to create
        private_key_file (str): private key file created with create_key_file
        passcode (str): passcode associated with the private_key
        common_name (str): common name for the resulting certificate
        dns_names (list): optional, a list of DNS Names to associate
            with this certificate
        ip_addresses (list): optional, a list of IP Addresses to associate
            with this certificate
        cert_length_days (int): optional, valid length of certificate
    """

    with open(private_key_file, 'rb') as fi:
        _private_key = fi.read()

    if passcode:
        private_key = serialization.load_pem_private_key(
                data=_private_key,
                password=passcode.encode(),
                backend=default_backend()
        )
    else:
        private_key = serialization.load_pem_private_key(
                _private_key, None, default_backend()
        )

    builder = x509.CertificateBuilder()

    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.issuer_name(
            x509.
            Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
    )

    valid_from = datetime.datetime.utcnow()
    valid_to = valid_from + datetime.timedelta(days=cert_length_days)

    builder = builder.not_valid_before(valid_from)
    builder = builder.not_valid_after(valid_to)

    builder = builder.subject_name(
            x509.
            Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
    )

    builder = builder.public_key(private_key.public_key())

    if dns_names:
        _dns_names = [x509.DNSName(n) for n in dns_names]
        builder = builder.add_extension(
                x509.SubjectAlternativeName(_dns_names), critical=False
        )

    if ip_addresses:
        _ip_addresses = [
            x509.IPAddress(ipaddress.IPv4Address(a)) for a in ip_addresses
        ]
        builder = builder.add_extension(
                x509.SubjectAlternativeName(_ip_addresses), critical=False
        )

    builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
    )

    builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    private_key.public_key()
            ),
            critical=False
    )

    builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                    private_key.public_key()
            ),
            critical=False
    )

    client_cert = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA512(),
            backend=default_backend()
    )

    with open(filename, 'wb') as fo:
        fo.write(client_cert.public_bytes(encoding=serialization.Encoding.PEM))
