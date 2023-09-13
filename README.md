# EasyOCSP

[![license](https://badgen.net/github/license/timokoessler/easy-ocsp)](https://github.com/timokoessler/easy-ocsp/blob/main/LICENSE)
[![Known Vulnerabilities](https://snyk.io/test/github/timokoessler/easy-ocsp/badge.svg)](https://snyk.io/test/github/timokoessler/easy-ocsp)
[![CodeFactor](https://www.codefactor.io/repository/github/timokoessler/easy-ocsp/badge)](https://www.codefactor.io/repository/github/timokoessler/easy-ocsp)
[![codecov](https://codecov.io/gh/timokoessler/easy-ocsp/graph/badge.svg?token=Q64CL70F8E)](https://codecov.io/gh/timokoessler/easy-ocsp)

EasyOCSP is an easy-to-use OCSP client for Node.js that can be used to check the revocation status of X.509 TLS certificates using the Online Certificate Status Protocol (OCSP). It's based on PKI.js but provides a much simpler API and additional features like OCSP nonce verification (RFC 8954).

A complete documentation can be found at [ocsp.tkoessler.de](https://ocsp.tkoessler.de).

## Getting started

You can install EasyOCSP using npm:

```sh
npm install easy-ocsp
```

The following example shows how to use EasyOCSP to check the revocation status of a certificate:

```typescript
import { getCertStatus } from 'easy-ocsp';

try {
    const ocspResult = await getCertStatus(/* PEM string, DER Buffer, X509Certificate */);

    if (ocspResult.status === 'revoked') {
        // Certificate is revoked
    } else if (ocspResult.status === 'good') {
        // Certificate is valid
    } else {
        // Certificate status is unknown
    }
} catch (e) {
    // Handle errors ...
}
```

### Get cert status by domain

EasyOCSP also provides a function to check the revocation status of a certificate by domain. This function will automatically download the certificate from the given domain and check its revocation status:

```typescript
import { getCertStatusByDomain } from 'easy-ocsp';

try {
    const ocspResult = await getCertStatusByDomain('example.com');
    // ...
} catch (e) {
    // Handle errors ...
}
```

## Advanced usage

### Get cert urls

You can use the `getCertUrls` function to get the URLs of the OCSP responder and the issuer certificate of a certificate. This is extracted from the certificate's `authorityInfoAccess` extension:

```typescript
import { getCertUrls } from 'easy-ocsp';

try {
    const { ocspUrl, issuerUrl } = await getCertUrls(/* PEM string, DER Buffer, X509Certificate */);
    // ...
} catch (e) {
    // Handle errors ...
}
```

### Download cert

You can use the `downloadCert` function to download the certificate of a domain. This function will return the certificate as a DER buffer:

```typescript
import { downloadCert } from 'easy-ocsp';

try {
    const cert = await downloadCert('example.com');
    // ...
} catch (e) {
    // Handle errors ...
}
```

### Advanced options

You can pass an options object to the `getCertStatus` and `getCertStatusByDomain` functions to configure the OCSP request. You can find a complete list of all options in the [documentation](https://ocsp.tkoessler.de/types/OCSPStatusConfig.html).

## Contact

If a public GitHub issue or discussion is not the right choice for your concern, you can contact me directly:

-   E-Mail: [info@timokoessler.de](mailto:info@timokoessler.de)

## Sources

-   [RFC 6960: X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP](https://datatracker.ietf.org/doc/html/rfc6960)
-   [RFC 8954: Online Certificate Status Protocol (OCSP) Nonce Extension](https://datatracker.ietf.org/doc/html/rfc8954)
-   [pkijs Docs](https://pkijs.org/docs/index.html)

## License

© Timo Kössler 2023
Released under the [MIT license](https://github.com/timokoessler/easy-ocsp/blob/main/LICENSE)
