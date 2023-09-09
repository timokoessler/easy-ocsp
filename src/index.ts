import { X509Certificate } from 'node:crypto';
import * as pkijs from 'pkijs';
import { convertToPkijsCert } from './convert';
import { buildOCSPRequest, getCAInfoUrls, parseOCSPResponse } from './ocsp';
import { getCertificateByHost } from './tls';

export type OCSPStatusConfig = {
    /**
     * The certificate that signs the OCSP response. If not provided, it will be downloaded if possible.
     */
    ca?: string | Buffer | X509Certificate | pkijs.Certificate;
    /**
     * The URL of the OCSP responder. By default, it will be extracted from the certificate.
     */
    ocspUrl?: string;
    /**
     * Whether to validate the signature of the OCSP response. Defaults to true.
     */
    validateSignature?: boolean;
};

async function downloadIssuerCert(cert: string | Buffer | X509Certificate | pkijs.Certificate): Promise<Buffer> {
    const { issuerUrl } = getCAInfoUrls(convertToPkijsCert(cert));
    const res = await fetch(issuerUrl);
    if (!res.ok) {
        throw new Error(`Issuer certificate download failed with status ${res.status} ${res.statusText} ${issuerUrl}`);
    }
    return Buffer.from(await res.arrayBuffer());
}

const defaultConfig: OCSPStatusConfig = {
    validateSignature: true,
};

/**
 * Get the status of a certificate
 * @param cert string | Buffer | X509Certificate | pkijs.Certificate
 * @param config Provide optional additional configuration
 * @returns Revocation status of the certificate and additional information if available
 * @throws Error if the OCSP request failed
 */
export async function getCertStatus(cert: string | Buffer | X509Certificate | pkijs.Certificate, config?: OCSPStatusConfig) {
    config = { ...defaultConfig, ...config };
    const certificate = convertToPkijsCert(cert);
    let issuerCertificate: pkijs.Certificate;
    if (!config.ca) {
        issuerCertificate = convertToPkijsCert(await downloadIssuerCert(certificate));
    } else {
        issuerCertificate = convertToPkijsCert(config.ca);
    }

    const ocspUrl = config.ocspUrl ? config.ocspUrl : getCAInfoUrls(certificate).ocspUrl;
    const ocspRequestBody = await buildOCSPRequest(certificate, issuerCertificate);

    const res = await fetch(ocspUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/ocsp-request',
        },
        body: Buffer.from(ocspRequestBody),
    });

    if (!res.ok) {
        throw new Error(`OCSP request failed with http status ${res.status} ${res.statusText}`);
    }

    return parseOCSPResponse(Buffer.from(await res.arrayBuffer()), certificate, issuerCertificate, config);
}

/**
 *
 * @param domain Domain to check the certificate for (e.g. 'github.com')
 * @param config Provide optional additional configuration
 * @returns Revocation status of the certificate and additional information if available
 * @throws Error if the certificate could not be retrieved or the OCSP request failed
 */
export async function getCertStatusByDomain(domain: string, config?: OCSPStatusConfig) {
    return getCertStatus(await getCertificateByHost(domain), config);
}

/**
 * Get the OCSP and issuer URLs from a certificate
 * @param cert string | Buffer | X509Certificate | pkijs.Certificate
 * @returns OCSP and issuer URLs
 * @throws Error if the certificate does not contain the required information
 */
export async function getCertURLs(
    cert: string | Buffer | X509Certificate | pkijs.Certificate,
): Promise<{ ocspUrl: string; issuerUrl: string }> {
    return getCAInfoUrls(convertToPkijsCert(cert));
}

export { getCertificateByHost };
