import { getCertStatus } from '../src';
import { readCertFile } from './test-helper';

let leCert: string;
let leRealRootCA: string;

beforeAll(async () => {
    leCert = await readCertFile('le-staging-revoked');
    leRealRootCA = await readCertFile('le-isrg-root-x1');
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
