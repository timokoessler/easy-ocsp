import { expect, beforeAll, test } from '@jest/globals';
import { getCertStatus, getCertURLs } from '../src';
import { readCertFile } from './test-helper';

let leCert: string;
let leIntermediateCA: string;
let leRealRootCA: string;
let selfSignedCert: string;
let leStagingExpired: string;

beforeAll(async () => {
    leCert = await readCertFile('le-staging-revoked');
    leIntermediateCA = await readCertFile('le-staging-artificial-apricot-r3');
    leRealRootCA = await readCertFile('le-isrg-root-x1');
    selfSignedCert = await readCertFile('self-signed');
    leStagingExpired = await readCertFile('le-staging-expired');
});

test('Invalid PEM', async () => {
    await expect(getCertStatus('1234')).rejects.toThrow('The certificate is not a valid PEM encoded X.509 certificate string');
});

test('Invalid certificate type', async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-expect-error
    await expect(getCertStatus([''])).rejects.toThrow(
        'Invalid certificate type. Expected string, Buffer, X509Certificate or pkijs.Certificate',
    );
});

test('Wrong ca', async () => {
    await expect(
        getCertStatus(leCert, {
            ca: leRealRootCA,
        }),
    ).rejects.toThrow('OCSP server response: unauthorized');
});

test('Wrong timeout', async () => {
    await expect(
        getCertStatus(leCert, {
            timeout: 0,
        }),
    ).rejects.toThrow('This operation was aborted');
});

test('No authority information', () => {
    expect(() => getCertURLs(selfSignedCert)).toThrow('Certificate does not contain authority information access extension');
});

test('Wrong ocsp server', async () => {
    await expect(
        getCertStatus(selfSignedCert, {
            ocspUrl: 'http://stg-r3.o.lencr.org',
            ca: leIntermediateCA,
        }),
    ).rejects.toThrow('OCSP server response: unauthorized');
});

test('Expired certificate', async () => {
    await expect(getCertStatus(leStagingExpired)).rejects.toThrow('The certificate is already expired');
});
