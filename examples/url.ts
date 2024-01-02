import { getCertStatusByDomain } from '../dist';

(async () => {
    try {
        const ocspResult = await getCertStatusByDomain('https://www.github.com');
        switch (ocspResult.status) {
            case 'good':
                console.log('Certificate is valid');
                break;
            case 'unknown':
                console.warn('Certificate status is unknown');
                break;
            case 'revoked':
                console.log(`Certificate was revoked at ${ocspResult.revocationTime}`);
                if (ocspResult.revocationReason) {
                    console.log(`Revocation reason: ${ocspResult.revocationReason}`);
                }
                break;
        }
    } catch (e) {
        console.error(e);
    }
})();
