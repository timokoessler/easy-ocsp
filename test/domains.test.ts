import { expect, describe, test } from '@jest/globals';
import { downloadCert, getCertStatus, getCertStatusByDomain } from '../src/index';

const domains = [
    'timokoessler.de',
    'github.com',
    'www.google.de',
    'stackoverflow.com',
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
    'www.entrust.com',
    'https://tkoessler.de',
];

describe('Get certificate status by domain', () => {
    for (const domain of domains) {
        test(domain, async () => {
            const response = await getCertStatusByDomain(domain, {
                timeout: 10000,
            });
            expect(response.status).toBe('good');
            expect(response.revocationTime).toBe(undefined);
            expect(response.producedAt).toBeInstanceOf(Date);
        });
    }

    test('Download cert should lead to same result', async () => {
        const response = await getCertStatus(await downloadCert('timokoessler.de'));
        expect(response.status).toBe('good');
        expect(response.revocationTime).toBe(undefined);
        expect(response.producedAt).toBeInstanceOf(Date);
    });
});
