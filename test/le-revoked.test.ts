import { X509Certificate } from 'crypto';
import { getCertStatus, getCertURLs, getRawOCSPResponse, OCSPRevocationReason } from '../src/index';
import { readCertFile } from './test-helper';

let cert: string;
let intermediateCA: string;

beforeAll(async () => {
    cert = await readCertFile('le-staging-revoked');
    intermediateCA = await readCertFile('le-staging-counterfeit-cashew-r10');
});

test('Check revoked Lets Encrypt cert', async () => {
    const result = await getCertStatus(cert);
    expect(result.status).toBe('revoked');
    expect(result.revocationTime?.getTime()).toBe(1715880904000);
    expect(result.revocationReason).toBe(OCSPRevocationReason.superseded);
});

test('Get OCSP and issuer URLs', async () => {
    const result = await getCertURLs(cert);
    expect(result.ocspUrl).toBe('http://stg-r10.o.lencr.org');
    expect(result.issuerUrl).toBe('http://stg-r10.i.lencr.org/');
});

test('Ask wrong ocsp server', async () => {
    await expect(
        getCertStatus(cert, {
            ocspUrl: 'http://ocsp.digicert.com',
        }),
    ).rejects.toThrow('OCSP server response: unauthorized');
});

test('Set ocsp url manually', async () => {
    const result = await getCertStatus(cert, {
        ocspUrl: 'http://stg-r10.o.lencr.org',
    });
    expect(result.status).toBe('revoked');
    expect(result.revocationTime?.getTime()).toBe(1715880904000);
});

test('Set ca manually', async () => {
    const result = await getCertStatus(cert, {
        ca: intermediateCA,
    });
    expect(result.status).toBe('revoked');
    expect(result.revocationTime?.getTime()).toBe(1715880904000);
    expect(result.revocationReason).toBe(OCSPRevocationReason.superseded);
});

test('Pass X509Certificate object', async () => {
    const result = await getCertStatus(new X509Certificate(cert));
    expect(result.status).toBe('revoked');
    expect(result.revocationTime?.getTime()).toBe(1715880904000);
    expect(result.revocationReason).toBe(OCSPRevocationReason.superseded);
});

test('Get raw response additionally', async () => {
    const result = await getCertStatus(cert, {
        rawResponse: true,
    });
    expect(result.status).toBe('revoked');
    expect(result.rawResponse).toBeInstanceOf(Buffer);
    expect(result.rawResponse?.length).toBeGreaterThan(10);
});

test('Get raw response', async () => {
    const result = await getRawOCSPResponse(cert);
    expect(result.rawResponse).toBeInstanceOf(Buffer);
    expect(result.rawResponse?.length).toBeGreaterThan(10);
    expect(result.nonce).toBeInstanceOf(Buffer);
    expect(result.issuerCert.replace(/[\n\r]/g, '')).toEqual(intermediateCA.replace(/[\n\r]/g, ''));
});
