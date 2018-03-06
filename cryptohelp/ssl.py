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


def create_key(passcode: bytes = b'') -> bytes:
    """Create a key suitable for use with ssl.

    Returns:
        A random key which can be used by the ssl tools in this module (bytes).
    """

    key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
    )

    return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.
            BestAvailableEncryption(passcode),
    )


def create_key_file(filename: str, passcode: bytes = b''):
    """Create a key file suitable for use with ssl.

    Returns:
        A random key which can be used by the ssl tools in this module.
    """

    with open(filename, "wb") as fo:
        fo.write(create_key(passcode))

    os.chmod(filename, 0o600)


def create_csr(
        private_key: bytes,
        passcode: bytes,
        common_name: bytes,
        dns_names: typing.List = [],
        ip_addresses: typing.List = [],
        country: str = "CA",
        province: str = "Ontario",
        locality: str = "Ottawa",
        organization: str = "CCX Technologies Inc.",
) -> bytes:
    """Create a x.509 Certificate Signing Request (CSR).

    Can be sent to another server which can create an Intermediate Certificate.

    Args:
        private_key (bytes): our private key created with create_key
        passcode (bytes): passcode associated with the private_key
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

    Returns:
        A signed Certificate Signing Request in PEM format (bytes).
    """

    _dns_names = [x509.DNSName(n) for n in dns_names]
    _ip_addresses = [
            x509.IPAddress(ipaddress.IPv4Address(str(a))) for a in ip_addresses
    ]

    key = serialization.load_pem_private_key(
            data=private_key, password=passcode, backend=default_backend()
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

    if _dns_names:
        csr = csr.add_extension(
                x509.SubjectAlternativeName(_dns_names), critical=False
        )

    if _ip_addresses:
        csr = csr.add_extension(
                x509.SubjectAlternativeName(_ip_addresses), critical=False
        )

    csr = csr.sign(key, hashes.SHA512(), default_backend())

    return csr.public_bytes(serialization.Encoding.PEM)


def create_certificate_from_csr(
        ca_private_key: bytes,
        ca_passcode: bytes,
        ca_certificate: bytes,
        csr: bytes,
        cert_length_days: int = 367
) -> bytes:
    """Create a x.509 Certificate from a Certificate Signing Request (CSR).

    Args:
        ca_private_key (bytes): the private key for the root certificate
        ca_passcode (bytes): passcode associated with the private_key
        ca_certificate (bytes): root certificate to create the intermediate
            certificate from in PEM format
        csr (bytes): CSR in PEM format
        cert_length_days (int): optional, valid length of certificate

    Returns:
        A signed Certificate in PEM format (bytes).
    """

    _csr = x509.load_pem_x509_csr(csr, default_backend())

    if not _csr.is_signature_valid:
        raise RuntimeError('CSR has invalid signature.')

    private_key = serialization.load_pem_private_key(
            data=ca_private_key,
            password=ca_passcode,
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
            x509.AuthorityKeyIdentifier.
            from_issuer_subject_key_identifier(issuer_ski),
            critical=False
    )

    client_cert = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA512(),
            backend=default_backend()
    )

    return client_cert.public_bytes(encoding=serialization.Encoding.PEM)


def create_certificate_from_ca(
        private_key: bytes,
        passcode: bytes,
        common_name: bytes,
        ca_certificate: bytes,
        dns_names: typing.List = [],
        ip_addresses: typing.List = [],
        country: str = "CA",
        province: str = "Ontario",
        locality: str = "Ottawa",
        organization: str = "CCX Technologies Inc.",
        cert_length_days: int = 367
) -> bytes:
    """Create a x.509 Certificate.

    Args:
        private_key (bytes): our private key created with create_key
        passcode (bytes): passcode associated with the private_key
        common_name (bytes): common name for the resulting certificate
        ca_certificate (bytes): Certificate Authority's Certificate
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

    Returns:
        A signed Certificate in PEM format (bytes).
    """

    _dns_names = [x509.DNSName(n) for n in dns_names]
    _ip_addresses = [
            x509.IPAddress(ipaddress.IPv4Address(str(a))) for a in ip_addresses
    ]

    private_key = serialization.load_pem_private_key(
            data=private_key, password=passcode, backend=default_backend()
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

    if _dns_names:
        builder = builder.add_extension(
                x509.SubjectAlternativeName(_dns_names), critical=False
        )

    if _ip_addresses:
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
            x509.AuthorityKeyIdentifier.
            from_issuer_subject_key_identifier(issuer_ski),
            critical=False
    )

    client_cert = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA512(),
            backend=default_backend()
    )

    return client_cert.public_bytes(encoding=serialization.Encoding.PEM)


def create_self_signed_certificate(
        private_key: bytes,
        passcode: bytes,
        common_name: bytes,
        dns_names: typing.List = [],
        ip_addresses: typing.List = [],
        country: str = "CA",
        province: str = "Ontario",
        locality: str = "Ottawa",
        organization: str = "CCX Technologies Inc.",
        cert_length_days: int = 367
) -> bytes:
    """Create a x.509 Certificate.

    Args:
        private_key (bytes): our private key created with create_key
        passcode (bytes): passcode associated with the private_key
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

    Returns:
        A signed Certificate in PEM format (bytes).
    """

    _dns_names = [x509.DNSName(n) for n in dns_names]
    _ip_addresses = [
            x509.IPAddress(ipaddress.IPv4Address(a)) for a in ip_addresses
    ]

    private_key = serialization.load_pem_private_key(
            data=private_key, password=passcode, backend=default_backend()
    )

    builder = x509.CertificateBuilder()

    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.issuer_name(
            x509.Name(
                    [
                            x509.NameAttribute(
                                    NameOID.COMMON_NAME, common_name
                            ),
                    ]
            )
    )

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

    if _dns_names:
        builder = builder.add_extension(
                x509.SubjectAlternativeName(_dns_names), critical=False
        )

    if _ip_addresses:
        builder = builder.add_extension(
                x509.SubjectAlternativeName(_ip_addresses), critical=False
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

    return client_cert.public_bytes(encoding=serialization.Encoding.PEM)
