import datetime
import time
import traceback
from functools import lru_cache

import cryptography
import requests
from asn1crypto import core, ocsp
from asn1crypto.ocsp import RevokedInfo, ResponseDataExtensions, ResponseDataExtension, Certificates
from cryptography import x509
from cryptography.hazmat._oid import OCSPExtensionOID
from cryptography.x509 import ocsp as pycaocsp
from cryptography.x509.ocsp import OCSPRequest
from oscrypto import asymmetric

from config import OCSP_SIGNERS
from data import XCertificate, DirectOCSPSigner, DelegatedOCSPSigner


def get_ttl_hash(seconds=60):
    return round(time.time() / seconds)


@lru_cache(maxsize=len(OCSP_SIGNERS))
def download_crl(crl_url: str, ttl_hash: int):
    print(f'Reloading CRL from source: {crl_url}')

    res = requests.get(crl_url)
    res.raise_for_status()

    crl_data = res.content
    crl = cryptography.x509.load_der_x509_crl(crl_data)

    if datetime.datetime.now(tz=datetime.timezone.utc) > crl.next_update_utc:
        raise RuntimeError("Expired CRL")

    return crl


def get_crl(crl_url: str, crl_cache_time: int, crl_issuer: XCertificate):
    crl = download_crl(crl_url, get_ttl_hash(crl_cache_time))

    if not crl.is_signature_valid(crl_issuer.pyca.public_key()):
        raise RuntimeError("Incorrectly signed CRL")

    return crl


def is_revoked(target_serial: int, crl):
    for r in crl:
        revoked_cert = crl.get_revoked_certificate_by_serial_number(r.serial_number)

        if target_serial == revoked_cert.serial_number:
            return revoked_cert.revocation_date_utc

    return None


def process_ocsp(data: bytes):
    try:
        ocsp_req = pycaocsp.load_der_ocsp_request(data)
        ocsp_res = generate_ocsp_res(ocsp_req)
    except Exception as e:
        traceback.print_exception(e)
        return ocsp.OCSPResponse({
            'response_status': 'internal_error'
        }).dump()

    return ocsp_res.dump()


def generate_ocsp_res(ocsp_req: OCSPRequest):
    sn_text = '{:02X}'.format(ocsp_req.serial_number)
    hash_alg = ocsp_req.hash_algorithm.name

    if hash_alg not in ["sha1", "sha256"]:
        return ocsp.OCSPResponse({"response_status": "malformed_request"})

    print(f'Cert {sn_text} - requested validation.')

    exts = []

    for ext in ocsp_req.extensions:
        if ext.oid == OCSPExtensionOID.NONCE:
            exts.append(ResponseDataExtension(value={
                "extn_id": "nonce",
                "critical": ext.critical,
                "extn_value": ext.value.nonce
            }))
        elif ext.critical:
            print(f'Cert {sn_text} - unknown critical extension, responding with unauthorized.')
            return ocsp.OCSPResponse({"response_status": "unauthorized"})

    for signer in OCSP_SIGNERS:
        if ocsp_req.issuer_key_hash == getattr(signer.ca_cert.oscrypto.public_key.asn1, hash_alg) and \
                ocsp_req.issuer_name_hash == getattr(signer.ca_cert.oscrypto.asn1.subject, hash_alg):
            break
    else:
        print(f'Cert {sn_text} - issuer unknown, responding with unauthorized.')
        return ocsp.OCSPResponse({
            'response_status': 'unauthorized'
        })

    produced_at = datetime.datetime.now(tz=datetime.timezone.utc).replace(microsecond=0)
    crl_issuer_cert = signer.crl_issuer_cert

    if not crl_issuer_cert:
        crl_issuer_cert = signer.ca_cert

    crl = get_crl(signer.crl_url, signer.crl_cache_time, crl_issuer_cert)
    revoked_time = is_revoked(ocsp_req.serial_number, crl)

    if not revoked_time:
        print(f'Cert {sn_text} - good.')
        cert_status = ocsp.CertStatus(
            name='good',
            value=core.Null()
        )
    else:
        print(f'Cert {sn_text} - revoked.')
        cert_status = ocsp.CertStatus(
            name='revoked',
            value=RevokedInfo(value={"revocation_time": revoked_time, "revocation_reason": "unspecified"})
        )

    if isinstance(signer, DirectOCSPSigner):
        responder_key_hash = signer.ca_cert.oscrypto.public_key.asn1.sha1
        responder_private_key = signer.ca_key.oscrypto
        send_certs = []
    elif isinstance(signer, DelegatedOCSPSigner):
        responder_key_hash = signer.ocsp_signer_cert.oscrypto.public_key.asn1.sha1
        responder_private_key = signer.ocsp_signer_key.oscrypto
        send_certs = [signer.ocsp_signer_cert.oscrypto.asn1]
    else:
        raise RuntimeError("Invalid signer class.")

    response_data = ocsp.ResponseData({
        'responder_id': ocsp.ResponderId(name='by_key', value=responder_key_hash),
        'produced_at': produced_at,
        'responses': [
            {
                'cert_id': {
                    'hash_algorithm': {
                        'algorithm': hash_alg
                    },
                    'issuer_name_hash': ocsp_req.issuer_name_hash,
                    'issuer_key_hash': ocsp_req.issuer_key_hash,
                    'serial_number': ocsp_req.serial_number,
                },
                'cert_status': cert_status,
                'this_update': produced_at - signer.this_update_offset,
                'next_update': produced_at + signer.next_update_offset,
                'single_extensions': []
            }
        ],
        'response_extensions': ResponseDataExtensions(value=exts)
    })

    # TODO hardcoded hash algorithm of the certificate
    signature_bytes = asymmetric.ecdsa_sign(responder_private_key, response_data.dump(), "sha256")
    signature_algorithm_id = '%s_%s' % ('sha256', 'ecdsa')

    resp = ocsp.OCSPResponse({
        'response_status': 'successful',
        'response_bytes': {
            'response_type': 'basic_ocsp_response',
            'response': {
                'tbs_response_data': response_data,
                'signature_algorithm': {'algorithm': signature_algorithm_id},
                'signature': signature_bytes,
                'certs': Certificates(value=send_certs)
            }
        }
    })

    return resp
