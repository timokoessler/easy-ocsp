import { test, describe, before } from 'node:test';
import { downloadIssuerCert, getCertStatus, getCertStatusByDomain, getCertURLs, downloadCert } from '../src';
import { readCertFile } from './test-helper';
import { rejects, throws } from 'node:assert';

let noOcspCert: string;
let caCert: string;
let validCert: string;
let leStagingExpired: string;
let leStagingRootCA: string;

describe('Error handling', () => {
    before(async () => {
        caCert = await readCertFile('0-cacert');
        validCert = await readCertFile('02-valid');
        noOcspCert = await readCertFile('self-signed-no-ocsp');
        leStagingExpired = await readCertFile('letsencrypt-staging-expired');
        leStagingRootCA = await readCertFile('letsencrypt-stg-root-x1');
    });

    test('Invalid PEM', async () => {
        await rejects(getCertStatus('1234'), {
            message: 'The certificate is not a valid PEM encoded X.509 certificate string',
        });
    });

    test('Invalid certificate type', async () => {
        // @ts-expect-error Testing invalid input
        await rejects(getCertStatus(['']), {
            message: 'Invalid certificate type. Expected string, Buffer, X509Certificate or pkijs.Certificate',
        });
    });

    test('No authority information', () => {
        throws(
            () => {
                getCertURLs(noOcspCert);
            },
            {
                message: 'Certificate does not contain authority information access extension',
            },
        );
    });

    test('Use CA cert for OCSP signature verification', async () => {
        await rejects(
            getCertStatus(validCert, {
                ca: caCert,
                ocspCertificate: caCert,
            }),
            {
                message: 'OCSP response signature verification failed',
            },
        );
    });

    test('Ask wrong ocsp server', async () => {
        await rejects(
            getCertStatus(validCert, {
                ocspUrl: 'http://ocsp.digicert.com',
            }),
            {
                message: 'OCSP server response: unauthorized',
            },
        );
    });

    test('Wrong timeout', async () => {
        await rejects(
            getCertStatus(validCert, {
                timeout: 0,
            }),
            {
                message: 'Failed to download issuer certificate: Operation timed out after 0ms',
            },
        );
    });

    test('Invalid url', async () => {
        await rejects(getCertStatusByDomain('test:// invalid %'), {
            message: 'Invalid URL',
        });
    });

    test('Invalid domain', async () => {
        await rejects(getCertStatusByDomain('enotfound.example.com'), {
            message: 'getaddrinfo ENOTFOUND enotfound.example.com',
        });
    });

    test('Abort getCertStatus', async () => {
        await rejects(getCertStatus(validCert, { timeout: 0 }), {
            message: 'Failed to download issuer certificate: Operation timed out after 0ms',
        });
    });

    test('Abort download issuer cert', async () => {
        await rejects(downloadIssuerCert(validCert, 0), {
            message: 'Failed to download issuer certificate: Operation timed out after 0ms',
        });
    });

    test('Invalid ocsp certificate format', async () => {
        await rejects(
            getCertStatus(validCert, {
                ocspCertificate: 'invalid-certificate-format',
            }),
            {
                message: 'The certificate is not a valid PEM encoded X.509 certificate string',
            },
        );
    });

    test('Server sends unrecognized name error', async () => {
        await rejects(downloadCert('no-cert-test.tkoessler.de'), {
            message: /SSL alert number 112/,
        });
    });

    test('Expired certificate', async () => {
        await rejects(getCertStatus(leStagingExpired), {
            message: 'The certificate is already expired',
        });
    });

    test('Wrong ca', async () => {
        await rejects(
            getCertStatus(validCert, {
                ca: leStagingRootCA,
            }),
            {
                message: 'Validation of OCSP response certificate chain failed',
            },
        );
    });

    test('Set ocsp server to non-existing URL', async () => {
        await rejects(
            getCertStatus(validCert, {
                ocspUrl: 'https://tkoessler.de/404-this-does-not-exist',
            }),
            {
                message: 'OCSP request failed with http status 404 Not Found',
            },
        );
    });

    test('Download issuercert with invalid cert', async () => {
        await rejects(downloadIssuerCert('--invalid-cert--'), {
            message: 'The certificate is not a valid PEM encoded X.509 certificate string',
        });
    });

    test('Valid cert without OCSP URL', async () => {
        await rejects(getCertStatus(await readCertFile('06-valid-no-ocsp-url')), {
            message: 'Certificate does not contain OCSP url',
        });
    });

    test('Valid cert without Issuer URL', async () => {
        await rejects(getCertStatus(await readCertFile('07-valid-no-issuer-url')), {
            message: 'Certificate does not contain issuer url',
        });
    });

    test('Valid cert with wrong Issuer URL', async () => {
        await rejects(getCertStatus(await readCertFile('08-valid-wrong-issuer-url')), {
            message: /Failed to download issuer certificate: fetch failed \(Error:/,
        });
    });

    test('Valid cert with wrong Issuer URL 2', async () => {
        await rejects(getCertStatus(await readCertFile('09-valid-wrong-issuer-url-02')), {
            message: 'Issuer certificate download failed with status 404 Not Found https://timokoessler.de/404-not-exists',
        });
    });

    test('Pass Pem encoded certificate as Buffer', async () => {
        await rejects(getCertStatus(Buffer.from(validCert, 'ascii')), {
            message: "Error during parsing of ASN.1 data. Data is not correct for 'Certificate'.",
        });
    });
});
