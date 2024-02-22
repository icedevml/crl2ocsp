from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

import cryptography.x509
import oscrypto.asymmetric


class XCertificate:
    def __init__(self, cert_file_pem: str):
        self._cert_file_pem = cert_file_pem

        with open(self._cert_file_pem, 'rb') as f:
            data = f.read()

        self.oscrypto = oscrypto.asymmetric.load_certificate(data)
        self.pyca = cryptography.x509.load_pem_x509_certificate(data)


class XPrivateKey:
    def __init__(self, key_file_pem: str, key_password: Optional[str] = None):
        self._key_file_pem = key_file_pem
        self._key_password = key_password

        with open(self._key_file_pem, 'rb') as f:
            data = f.read()

        self.oscrypto = oscrypto.asymmetric.load_private_key(data, key_password)


@dataclass
class BaseOCSPSigner:
    # CRL to be used for figuring out the certificate statuses
    crl_url: str
    # How long should the CRL be cached (seconds)
    crl_cache_time: int

    # Certificate of the CA that issued the CRL
    crl_issuer_cert: None

    # Hash algorithm to be used when signing OCSP responses
    # Could be one of: sha1, sha256, sha384, sha512
    hash_algo: str

    # added to the actual current time in order to compute "this update" value,
    # slightly backdated by default to avoid problems
    this_update_offset: timedelta

    # added to the actual current time in order to compute "next update" value,
    # by default set to 1 minute to prevent from caching
    next_update_offset: timedelta


@dataclass
class DirectOCSPSigner(BaseOCSPSigner):
    # Certificate of the issuer
    ca_cert: XCertificate
    # CA Key to sign OCSP response
    ca_key: XPrivateKey


@dataclass
class DelegatedOCSPSigner(BaseOCSPSigner):
    # Certificate of the issuer
    ca_cert: XCertificate
    # OCSP Signer Certificate
    ocsp_signer_cert: XCertificate
    # OCSP Signer Key
    ocsp_signer_key: XPrivateKey
