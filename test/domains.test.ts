import { getCertStatusByDomain } from '../src/index';

const domains = ['timokoessler.de', 'github.com', 'www.google.de', 'stackoverflow.com'];

describe('Get certificate status by domain', () => {
    for (const domain of domains) {
        test(domain, async () => {
            expect((await getCertStatusByDomain(domain)).status).toBe('good');
        });
    }
});
