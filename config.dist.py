from datetime import timedelta

from data import XCertificate, XPrivateKey, DirectOCSPSigner, DelegatedOCSPSigner

OCSP_SIGNERS = [
    DirectOCSPSigner(
        crl_url='http://my-ca.example.com/crl',
        crl_issuer_cert=None,  # same as ca_cert
        crl_cache_time=60,
        ca_cert=XCertificate('intermediate_ca.pem'),
        ca_key=XPrivateKey('intermediate_ca.key', 'password'),
        this_update_offset=timedelta(minutes=-1),
        next_update_offset=timedelta(minutes=1)
    ),
    DelegatedOCSPSigner(
        crl_url='http://my-ca.example.com/crl',
        crl_issuer_cert=None,  # same as ca_cert
        crl_cache_time=60,
        ca_cert=XCertificate('intermediate_ca.pem'),
        ocsp_signer_cert=XCertificate('ocsp_signer.pem'),
        ocsp_signer_key=XPrivateKey(
            key_file_pem='ocsp_signer.key',
            key_password='xxx'
        ),
        this_update_offset=timedelta(minutes=-1),
        next_update_offset=timedelta(minutes=1)
    )
]
