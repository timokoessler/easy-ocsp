import * as pkijs from 'pkijs';
import { fromBER } from 'asn1js';
import { X509Certificate } from 'node:crypto';

/**
 * Convert a PEM encoded X.509 certificate to a pkijs.Certificate object
 * @param pem The certificate to convert as a string
 * @returns A pkijs.Certificate object
 */
function pemToCert(pem: string) {
    try {
        const base64 = pem.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, '');
        const der = Buffer.from(base64, 'base64');
        const asn1 = fromBER(new Uint8Array(der).buffer);
        return new pkijs.Certificate({ schema: asn1.result });
    } catch {
        throw new Error('The certificate is not a valid PEM encoded X.509 certificate string');
    }
}

/**
 * Convert a certificate to a pkijs.Certificate object
 * @param cert The certificate to convert as a string, Buffer, X509Certificate or pkijs.Certificate
 * @returns A pkijs.Certificate object
 */
export function convertToPkijsCert(cert: string | Buffer | X509Certificate | pkijs.Certificate) {
    if (typeof cert === 'string') {
        return pemToCert(cert);
    }
    if (cert instanceof X509Certificate) {
        return pemToCert(cert.toString());
    }
    if (cert instanceof Buffer) {
        return pkijs.Certificate.fromBER(cert);
    }
    if (cert instanceof pkijs.Certificate) {
        return cert;
    }
    throw new Error('Invalid certificate type. Expected string, Buffer, X509Certificate or pkijs.Certificate');
}

/**
 * Convert a pkijs.Certificate object to a PEM encoded X.509 certificate
 * @param cert The certificate to convert
 * @returns The certificate as a PEM encoded string
 */
export function convertPkijsCertToPem(cert: pkijs.Certificate) {
    const der = Buffer.from(cert.toSchema().toBER(false));
    const base64 = der.toString('base64');
    return `-----BEGIN CERTIFICATE-----\n${base64.match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----\n`;
}
