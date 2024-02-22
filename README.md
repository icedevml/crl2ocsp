# CRL to OCSP Proxy

OCSP Responder which relies solely on the CRL lists consumed from an external source.
Could be useful to enhance your PKI with OCSP service wherever it is not supported out of the box
by the tools that you are already using.

## Features

* Supports both SHA-1 and SHA-256 hash algorithms for Certificate ID.
* Supports SHA-1/SHA-256/SHA-384/SHA-512 hash algorithms for signing the OCSP response.
* Could answer on behalf of multiple CAs at once (with distinct CRLs).
* Supports delegated OCSP signing.

## Known limitations

* Asking about nonexistent certificates would also return a "good" OCSP response - this responder
  only knows if a given certificate was revoked or not, although it doesn't know if it was ever issued.
  All production tools should perform the certificate chain validation anyway, before querying the OCSP server.
* Bulk OCSP requests are not supported - you can only ask about one certificate at a time.
  Most tools would not send batch requests anyway.
* This OCSP server would return the `unauthorized` error code when the queried certificate is related with
  an unrecognized issuer CA. Thus, all your certificate issuers must be explicitly registered in the configuration.
* The current implementation might not work well with large CRLs (solvable with background workers).

ocspbuilder