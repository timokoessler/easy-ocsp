import { test, describe, before } from 'node:test';
import { equal, rejects } from 'node:assert';
import { X509Certificate } from 'node:crypto';
import { downloadIssuerCert, getCertStatus, getCertURLs, getRawOCSPResponse, OCSPRevocationReason } from '../src/index';
import { readCertFile } from './test-helper';
import { convertToPkijsCert } from '../src/convert';

let cert: string;
let intermediateCA: string;

describe('Revoked Lets Encrypt certificate', () => {
    before(async () => {
        cert = await readCertFile('le-staging-revoked');
        intermediateCA = await readCertFile('le-staging-false-fennel-e6');
    });

    test('Check revoked Lets Encrypt cert', async () => {
        const result = await getCertStatus(cert);
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1739030462000);
        equal(result.revocationReason, OCSPRevocationReason.superseded);
    });

    test('Get OCSP and issuer URLs', () => {
        const result = getCertURLs(cert);
        equal(result.ocspUrl, 'http://stg-e6.o.lencr.org');
        equal(result.issuerUrl, 'http://stg-e6.i.lencr.org/');
    });

    test('Ask wrong ocsp server', async () => {
        await rejects(
            getCertStatus(cert, {
                ocspUrl: 'http://ocsp.digicert.com',
            }),
            {
                message: 'OCSP server response: unauthorized',
            },
        );
    });

    test('Set ocsp url manually', async () => {
        const result = await getCertStatus(cert, {
            ocspUrl: 'http://stg-r10.o.lencr.org',
        });
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1739030462000);
    });

    test('Set ca manually', async () => {
        const result = await getCertStatus(cert, {
            ca: intermediateCA,
        });
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1739030462000);
        equal(result.revocationReason, OCSPRevocationReason.superseded);
    });

    test('Pass X509Certificate object', async () => {
        const result = await getCertStatus(new X509Certificate(cert));
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1739030462000);
        equal(result.revocationReason, OCSPRevocationReason.superseded);
    });

    test('Get raw response additionally', async () => {
        const result = await getCertStatus(cert, {
            rawResponse: true,
        });
        equal(result.status, 'revoked');
        equal(result.rawResponse instanceof Buffer, true);
        equal((result.rawResponse?.length || -1) > 10, true);
    });

    test('Get raw response', async () => {
        const result = await getRawOCSPResponse(cert);
        equal(result.rawResponse instanceof Buffer, true);
        equal(result.rawResponse?.length > 10, true);
        equal((result.rawResponse?.length || -1) > 10, true);
        equal(result.nonce instanceof Buffer, true);
        equal(result.issuerCert.replace(/[\n\r]/g, ''), intermediateCA.replace(/[\n\r]/g, ''));
    });

    test('Download issuer cert', async () => {
        const issuerCert = await downloadIssuerCert(cert);
        const expectedIssuerCert = convertToPkijsCert(intermediateCA);
        equal(JSON.stringify(issuerCert.toJSON()), JSON.stringify(expectedIssuerCert.toJSON()));
    });
});
