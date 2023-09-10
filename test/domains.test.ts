import { getCertStatusByDomain } from '../src/index';

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
];

describe('Get certificate status by domain', () => {
    for (const domain of domains) {
        test(domain, async () => {
            const response = await getCertStatusByDomain(domain);
            expect(response.status).toBe('good');
            expect(response.revocationTime).toBe(undefined);
            expect(response.producedAt).toBeInstanceOf(Date);
        });
    }
});
