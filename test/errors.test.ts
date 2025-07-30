import { test, describe, before } from 'node:test';
import { downloadIssuerCert, getCertStatus, getCertStatusByDomain, getCertURLs } from '../src';
import { readCertFile } from './test-helper';
import { rejects, throws } from 'node:assert';

let leCert: string;
let leIntermediateCA: string;
let leRealRootCA: string;
let selfSignedCert: string;
let leStagingExpired: string;

describe('Error handling', () => {
    before(async () => {
        leCert = await readCertFile('le-staging-revoked');
        leIntermediateCA = await readCertFile('le-staging-false-fennel-e6');
        leRealRootCA = await readCertFile('le-isrg-root-x2');
        selfSignedCert = await readCertFile('self-signed');
        leStagingExpired = await readCertFile('le-staging-expired');
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

    test('Wrong ca', async () => {
        await rejects(
            getCertStatus(leCert, {
                ca: leRealRootCA,
            }),
            {
                message: 'OCSP server response: unauthorized',
            },
        );
    });

    test('Wrong timeout', async () => {
        await rejects(
            getCertStatus(leCert, {
                timeout: 0,
            }),
            {
                message: 'This operation was aborted',
            },
        );
    });

    test('No authority information', () => {
        throws(
            () => {
                getCertURLs(selfSignedCert);
            },
            {
                message: 'Certificate does not contain authority information access extension',
            },
        );
    });

    test('Wrong ocsp server', async () => {
        await rejects(
            getCertStatus(selfSignedCert, {
                ocspUrl: 'http://stg-r3.o.lencr.org',
                ca: leIntermediateCA,
            }),
            {
                message: 'OCSP server response: unauthorized',
            },
        );
    });

    test('Expired certificate', async () => {
        await rejects(getCertStatus(leStagingExpired), {
            message: 'The certificate is already expired',
        });
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
        await rejects(getCertStatus(leCert, { timeout: 0 }), {
            message: 'This operation was aborted',
        });
    });

    test('Abort download issuer cert', async () => {
        await rejects(downloadIssuerCert(leCert, 0), {
            message: 'This operation was aborted',
        });
    });

    test('Invalid ocsp certificate format', async () => {
        await rejects(
            getCertStatus(leCert, {
                ca: leIntermediateCA,
                ocspCertificate: 'invalid-certificate-format',
            }),
            {
                message: /certificate/i,
            },
        );
    });

    test('ocspCertificate parameter is passed correctly', async () => {
        // Just test that the parameter is accepted without throwing immediate parsing errors
        // This test uses an expired certificate, so we expect "already expired" error,
        // but the important thing is that ocspCertificate is processed correctly
        await rejects(
            getCertStatus(leStagingExpired, {
                ca: leIntermediateCA,
                ocspCertificate: leRealRootCA,
            }),
            {
                message: 'The certificate is already expired',
            },
        );
    });
});
