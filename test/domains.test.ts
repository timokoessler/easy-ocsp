import { describe, test } from 'node:test';
import { equal } from 'node:assert';
import { downloadCert, getCertStatus, getCertStatusByDomain } from '../src/index';

const domains = [
    'github.com',
    'www.google.de',
    'www.microsoft.com',
    'www.apple.com',
    'www.amazon.de',
    'www.meta.com',
    'www.sap.com',
    'www.oracle.com',
    'www.digicert.com',
    'www.comodoca.com',
    'www.globalsign.com',
    'www.godaddy.com',
    'www.rapidssl.com',
    'https://www.entrust.com',
];

describe('Get certificate status by domain', () => {
    for (const domain of domains) {
        test(domain, async () => {
            const response = await getCertStatusByDomain(domain, {
                timeout: 10000,
            });
            equal(response.status, 'good');
            equal(response.revocationTime, undefined);
            equal(response.producedAt instanceof Date, true);
        });
    }

    test('Download cert should work as well', async () => {
        const response = await getCertStatus(await downloadCert('example.com'));
        equal(response.status, 'good');
        equal(response.revocationTime, undefined);
        equal(response.producedAt instanceof Date, true);
    });
});
