import { getCertStatus, getCertURLs } from '../src/index';
import { readCertFile } from './test-helper';

let cert: string;
let intermediateCA: string;

beforeAll(async () => {
    cert = await readCertFile('le-staging-revoked');
    intermediateCA = await readCertFile('le-staging-artificial-apricot-r3');
});

test('Check revoked Lets Encrypt cert', async () => {
    const result = await getCertStatus(cert);
    expect(result.status).toBe('revoked');
    expect(result.revocationTime?.toISOString()).toBe('2023-09-06T14:14:10.000Z');
});

test('Get OCSP and issuer URLs', async () => {
    const result = await getCertURLs(cert);
    expect(result.ocspUrl).toBe('http://stg-r3.o.lencr.org');
    expect(result.issuerUrl).toBe('http://stg-r3.i.lencr.org/');
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
        ocspUrl: 'http://stg-r3.o.lencr.org',
    });
    expect(result.status).toBe('revoked');
    expect(result.revocationTime?.toISOString()).toBe('2023-09-06T14:14:10.000Z');
});

test('Set ca manually', async () => {
    const result = await getCertStatus(cert, {
        ca: intermediateCA,
    });
    expect(result.status).toBe('revoked');
    expect(result.revocationTime?.toISOString()).toBe('2023-09-06T14:14:10.000Z');
});
