import { getCertStatus } from '../dist';

const pem = `-----BEGIN CERTIFICATE-----
MIIFADCCA+igAwIBAgISBMEOHi9wmW2BPAaqd1BBZe8FMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMzExMTgyMTIyMDJaFw0yNDAyMTYyMTIyMDFaMBoxGDAWBgNVBAMT
D3RpbW9rb2Vzc2xlci5kZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AL5hHjmCNo9GODE7/YFCaq9heN8x1cLrLJwW+unRLYsVIA8CaI1+SU/53pa/EW4Z
C5a7aqx2EUEWOsHX0b9aMvXNRpbGWjkhzXDghiXw7JMTzAj6qaJBC7V8SO0/i0S3
xmAK4fNvO/fWRLcT/qEkUCFYl4cKdA8LoFiUlPmJJ0J1lCzbJjhhC2dp0Xbcij7o
MTq6Hl4YmQVMXXPLLPuK58aAZ6uxClU9XA1gCDZKguFlQX47LR2i2oMQWhM3+QuZ
E5urvjGkKEeTgaaZ/ATqA0Sn9AdoEgnyOGs0ESXwpn1riXw3vnZpql5c8du38XFS
W5f8br7OO/fyHWsHTRjnEwsCAwEAAaOCAiYwggIiMA4GA1UdDwEB/wQEAwIFoDAd
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNV
HQ4EFgQUIV0BsjybJGGnHehozlkAS933wmkwHwYDVR0jBBgwFoAUFC6zF7dYVsuu
UAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8v
cjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9y
Zy8wLQYDVR0RBCYwJIIRKi50aW1va29lc3NsZXIuZGWCD3RpbW9rb2Vzc2xlci5k
ZTATBgNVHSAEDDAKMAgGBmeBDAECATCCAQYGCisGAQQB1nkCBAIEgfcEgfQA8gB3
AEiw42vapkc0D+VqAvqdMOscUgHLVt0sgdm7v6s52IRzAAABi+SG0IoAAAQDAEgw
RgIhAOlrGI85GmgpULep55aPxRZD0w4YacA845hfVgf8wacnAiEA8qOOLHbf8s/M
9zjgFJpmERBMBD0giq+RbU/z40LN4poAdwB2/4g/Crb7lVHCYcz1h7o0tKTNuync
aEIKn+ZnTFo6dAAAAYvkhtEtAAAEAwBIMEYCIQCqHPRRCI5rgWbGtmEWQzW1ROuH
Wmtq0C7po0Z2x45QtQIhAL6I6YV9+KGxvUzaHNm5gWhkfMeEIvNCwX4qMzsmoUwv
MA0GCSqGSIb3DQEBCwUAA4IBAQChQwnAeQggF6R8eOIqJjyC5oDaCAO6YMksPXtf
QBcEwEMRiAQLu6LrIiQTZ3qlVlcy+pCriqO0M2ZSGOO9cnUOni1FBq4SHn1cEJww
Fa3n1w1EXuMhzu+tWbOPB/qUxCwlVVKwTqPaOtxvEPBG6Cq2zXcWMiFKJF1Mhtvf
28WBCg3FYxwFAaro+dbhhZgZjme7o4HVm6CBiJnoWTBunQJQv4N5en93mmQ/zNuE
nYyncUGfxzND+umclp2SM29pU0jwrjZg+9e0ZZEqSKr5to3D1Nxyr9oTYri5H8U/
MPea67E7SY5zIULkNkaGx0TeijsyGFS4gfXGH4wIcoaO580N
-----END CERTIFICATE-----
`;

(async () => {
    try {
        // Urls are converted to the domain automatically
        const ocspResult = await getCertStatus(pem);
        switch (ocspResult.status) {
            case 'good':
                console.log('Certificate is valid');
                break;
            case 'unknown':
                console.warn('Certificate status is unknown');
                break;
            case 'revoked':
                console.log(`Certificate was revoked at ${ocspResult.revocationTime}`);
                if (ocspResult.revocationReason) {
                    console.log(`Revocation reason: ${ocspResult.revocationReason}`);
                }
                break;
        }
    } catch (e) {
        console.error(e);
    }
})();
