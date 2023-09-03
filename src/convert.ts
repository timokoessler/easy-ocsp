import * as pkijs from 'pkijs';
import { fromBER } from 'asn1js';
import { X509Certificate } from 'crypto';
import type { SupportedCertType } from './index';

export function pemToCert(pem: string) {
    const base64 = pem.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, '');
    const der = Buffer.from(base64, 'base64');
    const asn1 = fromBER(new Uint8Array(der).buffer);
    return new pkijs.Certificate({ schema: asn1.result });
}

export function derToCert(der: Buffer) {
    return pkijs.Certificate.fromBER(der);
}

export function convertToPkijsCert(cert: SupportedCertType) {
    if (typeof cert === 'string') {
        return pemToCert(cert);
    } else if (cert instanceof X509Certificate) {
        return pemToCert(cert.toString());
    } else if (cert instanceof Buffer) {
        return derToCert(cert);
    } else if (cert instanceof pkijs.Certificate) {
        return cert;
    } else {
        throw new Error('Invalid certificate type');
    }
}
