# EasyOCSP

**Work in progress**

EasyOCSP is an easy-to-use OCSP client for Node.js that can be used to check the revocation status of X.509 TLS certificates using the Online Certificate Status Protocol (OCSP). Its based on PKI.js but provides a much simpler API and additional features like OCSP nonce verification (RFC 8954).

A complete documentation can be found at [ocsp.tkoessler.de](https://ocsp.tkoessler.de).

## Getting started

You can install EasyOCSP using npm:

```bash
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
