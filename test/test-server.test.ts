import { test, describe, before } from 'node:test';
import { equal } from 'node:assert';
import { X509Certificate } from 'node:crypto';
import { downloadIssuerCert, getCertStatus, getCertURLs, getRawOCSPResponse, OCSPRevocationReason } from '../src/index';
import { readCertFile } from './test-helper';
import { bufferToArrayBuffer, convertToPkijsCert } from '../src/convert';
import { setTimeout } from 'node:timers/promises';

let caCert: string;
let ocspServerCert: string;
let validCert: string;
let revokedCert01: string;
let revokedCert02: string;
let revokedCert03: string;

describe('Test multiple certificates with test server', async () => {
    before(async () => {
        caCert = await readCertFile('0-cacert');
        ocspServerCert = await readCertFile('01-ocspcert');
        validCert = await readCertFile('02-valid');
        revokedCert01 = await readCertFile('03-revoked-01');
        revokedCert02 = await readCertFile('04-revoked-02');
        revokedCert03 = await readCertFile('05-revoked-03');
    });

    test('Get OCSP and issuer URLs', () => {
        const result = getCertURLs(validCert);
        equal(result.ocspUrl, 'https://ocsp-test-responder.tkoessler.de');
        equal(result.issuerUrl, 'https://ocsp-test-responder.tkoessler.de/cacert.pem');
    });

    test('Get OCSP status for valid cert', async () => {
        const result = await getCertStatus(validCert);
        equal(result.status, 'good');
        equal(result.revocationTime, undefined);
        equal(result.revocationReason, undefined);
        equal(result.ocspUrl, 'https://ocsp-test-responder.tkoessler.de');
    });

    test('Get OCSP status for valid cert with provided CA cert', async () => {
        const result = await getCertStatus(validCert, {
            ca: caCert,
        });
        equal(result.status, 'good');
        equal(result.revocationTime, undefined);
        equal(result.revocationReason, undefined);
    });

    test('Get OCSP status for valid cert with provided OCSP cert', async () => {
        const result = await getCertStatus(validCert, {
            ca: caCert,
            ocspCertificate: ocspServerCert,
            ocspUrl: 'https://ocsp-test-responder.tkoessler.de',
        });
        equal(result.status, 'good');
        equal(result.revocationTime, undefined);
        equal(result.revocationReason, undefined);
    });

    test('Get OCSP status for revoked cert', async () => {
        const result = await getCertStatus(revokedCert01);
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1753989043000);
        equal(result.revocationReason, undefined);
        equal(result.ocspUrl, 'https://ocsp-test-responder.tkoessler.de');
        equal(result.producedAt!.getTime() > 1753989043000, true);
    });

    await setTimeout(100);

    test('Get OCSP status for revoked cert with provided CA cert', async () => {
        const result = await getCertStatus(revokedCert01, {
            ca: caCert,
            ocspUrl: 'https://ocsp-test-responder.tkoessler.de',
        });
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1753989043000);
        equal(result.revocationReason, undefined);
        equal(result.ocspUrl, 'https://ocsp-test-responder.tkoessler.de');
        equal(result.producedAt!.getTime() > 1753989043000, true);
    });

    test('Get OCSP status for revoked cert with provided CA cert and OCSP cert', async () => {
        const result = await getCertStatus(revokedCert01, {
            ca: caCert,
            ocspUrl: 'https://ocsp-test-responder.tkoessler.de',
            ocspCertificate: ocspServerCert,
        });
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1753989043000);
        equal(result.revocationReason, undefined);
        equal(result.ocspUrl, 'https://ocsp-test-responder.tkoessler.de');
        equal(result.producedAt!.getTime() > 1753989043000, true);
    });

    test('Download issuer cert', async () => {
        const issuerCert = await downloadIssuerCert(revokedCert01);
        const expectedIssuerCert = convertToPkijsCert(caCert);
        equal(JSON.stringify(issuerCert.toJSON()), JSON.stringify(expectedIssuerCert.toJSON()));
    });

    test('Pass X509Certificate object', async () => {
        const result = await getCertStatus(new X509Certificate(revokedCert01));
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1753989043000);
        equal(result.revocationReason, undefined);
    });

    test('Pass Buffer', async () => {
        const base64 = revokedCert01.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, '');
        const der = Buffer.from(base64, 'base64');
        const result = await getCertStatus(der);
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1753989043000);
        equal(result.revocationReason, undefined);
    });

    test('Pass ArrayBuffer', async () => {
        const base64 = revokedCert01.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, '');
        const der = bufferToArrayBuffer(Buffer.from(base64, 'base64'));
        const result = await getCertStatus(der);
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1753989043000);
        equal(result.revocationReason, undefined);
    });

    test('Get OCSP status for revoked cert 02', async () => {
        const result = await getCertStatus(revokedCert02);
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1754054706000);
        equal(result.revocationReason, OCSPRevocationReason.unspecified);
        equal(result.ocspUrl, 'https://ocsp-test-responder.tkoessler.de');
        equal(result.producedAt!.getTime() > 1754054706000, true);
    });

    await setTimeout(100);

    test('Get OCSP status and raw response for revoked cert 02', async () => {
        const result = await getCertStatus(revokedCert02, {
            rawResponse: true,
        });
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1754054706000);
        equal(result.revocationReason, OCSPRevocationReason.unspecified);
        equal(result.ocspUrl, 'https://ocsp-test-responder.tkoessler.de');
        equal(result.producedAt!.getTime() > 1754054706000, true);
        equal(result.rawResponse instanceof Buffer, true);
        equal((result.rawResponse?.length || -1) > 10, true);
    });

    test('Get raw response 02', async () => {
        const result = await getRawOCSPResponse(revokedCert02);
        equal(result.rawResponse instanceof Buffer, true);
        equal(result.rawResponse?.length > 10, true);
        equal((result.rawResponse?.length || -1) > 10, true);
        equal(result.nonce instanceof Buffer, true);
        equal(result.issuerCert.replace(/[\n\r]/g, ''), caCert.replace(/[\n\r]/g, ''));
    });

    test('Use OCSP cert as CA cert', async () => {
        const result = await getCertStatus(validCert, {
            ca: ocspServerCert,
        });
        equal(result.status, 'unknown');
        equal(result.revocationTime, undefined);
        equal(result.revocationReason, undefined);
    });

    test('Get OCSP status for revoked cert 03', async () => {
        const result = await getCertStatus(revokedCert03);
        equal(result.status, 'revoked');
        equal(result.revocationTime?.getTime(), 1754058063000);
        equal(result.revocationReason, OCSPRevocationReason.superseded);
        equal(result.ocspUrl, 'https://ocsp-test-responder.tkoessler.de');
        equal(result.producedAt!.getTime() > 1754058063000, true);
    });

    test('Get raw response without nonce', async () => {
        const result = await getRawOCSPResponse(revokedCert02, {
            enableNonce: false,
        });
        equal(result.rawResponse instanceof Buffer, true);
        equal(result.rawResponse?.length > 10, true);
        equal((result.rawResponse?.length || -1) > 10, true);
        equal(result.nonce, undefined);
        equal(result.issuerCert.replace(/[\n\r]/g, ''), caCert.replace(/[\n\r]/g, ''));
    });
});
