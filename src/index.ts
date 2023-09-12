import { X509Certificate } from 'node:crypto';
import * as pkijs from 'pkijs';
import { convertToPkijsCert } from './convert';
import { buildOCSPRequest, getCAInfoUrls, parseOCSPResponse } from './ocsp';
import { downloadCert } from './tls';

/**
 * Additional optional configuration
 */
export type OCSPStatusConfig = {
    /**
     * The issuer certificate authority. If not provided, it will be downloaded from the issuer URL. If you already have the issuer certificate, you can provide it here to improve performance.
     */
    ca?: string | Buffer | X509Certificate | pkijs.Certificate;
    /**
     * The URL of the OCSP responder. By default, it will be extracted from the certificate. If you already know the OCSP responder URL, you can provide it here.
     */
    ocspUrl?: string;
    /**
     * Whether to validate the signature of the OCSP response. This is enabled by default and should only be disabled for debugging purposes.
     * @defaultValue true
     */
    validateSignature?: boolean;
    /**
     * Timeout in milliseconds for the OCSP request and download of the issuer certificate. If the request takes longer than this, it will be aborted.
     * @defaultValue 6000
     */
    timeout?: number;
    /**
     * Whether to include a nonce in the OCSP request. This is enabled by default because it enhances security.
     * @defaultValue true
     */
    enableNonce?: boolean;
};

export type OCSPStatusResponse = {
    /**
     * Revocation status of the certificate
     */
    status: 'good' | 'revoked' | 'unknown';
    /**
     * The OCSP responder URL
     */
    ocspUrl: string;
    /**
     * Time when the certificate was revoked. Only and not always available if the status is 'revoked'.
     */
    revocationTime?: Date;
    /**
     * The time at or before which newer information will be available about the status of the certificate.
     */
    nextUpdate?: Date;
    /**
     * The most recent time at which the status being indicated is known by the responder to have been correct.
     */
    thisUpdate?: Date;
    /**
     * The time at which the response was produced.
     */
    producedAt?: Date;
};

async function downloadIssuerCert(cert: string | Buffer | X509Certificate | pkijs.Certificate, config: OCSPStatusConfig): Promise<Buffer> {
    const { issuerUrl } = getCAInfoUrls(convertToPkijsCert(cert));
    const ac = new AbortController();
    const timeout = setTimeout(() => ac.abort(), config.timeout);
    const res = await fetch(issuerUrl, {
        signal: ac.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) {
        throw new Error(`Issuer certificate download failed with status ${res.status} ${res.statusText} ${issuerUrl}`);
    }
    return Buffer.from(await res.arrayBuffer());
}

const defaultConfig: OCSPStatusConfig = {
    validateSignature: true,
    enableNonce: true,
    timeout: 6000,
};

/**
 * Get the revocation status of a certificate.
 * @param cert string | Buffer | X509Certificate | pkijs.Certificate
 * @param config Provide optional additional configuration
 * @returns Revocation status of the certificate and additional information if available
 * @throws Error if the OCSP request failed
 * @throws AbortError if the request timed out
 */
export async function getCertStatus(cert: string | Buffer | X509Certificate | pkijs.Certificate, config?: OCSPStatusConfig) {
    config = { ...defaultConfig, ...config };
    const certificate = convertToPkijsCert(cert);

    if (!config.ocspUrl) {
        config.ocspUrl = getCAInfoUrls(certificate).ocspUrl;
    }

    let issuerCertificate: pkijs.Certificate;
    if (!config.ca) {
        issuerCertificate = convertToPkijsCert(await downloadIssuerCert(certificate, config));
    } else {
        issuerCertificate = convertToPkijsCert(config.ca);
    }

    const { ocspReq, nonce } = await buildOCSPRequest(certificate, issuerCertificate, config);

    const ac = new AbortController();
    const timeout = setTimeout(() => ac.abort(), config.timeout);
    const res = await fetch(config.ocspUrl as string, {
        method: 'POST',
        signal: ac.signal,
        headers: {
            'Content-Type': 'application/ocsp-request',
        },
        body: Buffer.from(ocspReq),
    });
    clearTimeout(timeout);

    if (!res.ok) {
        throw new Error(`OCSP request failed with http status ${res.status} ${res.statusText}`);
    }

    return parseOCSPResponse(Buffer.from(await res.arrayBuffer()), certificate, issuerCertificate, config, nonce);
}

/**
 * Download the tls certificate that is used for a domain and check its revocation status. This is a convenience function that combines downloadCert and getCertStatus.
 * @param domain Domain to check the certificate for (e.g. 'github.com')
 * @param config Provide optional additional configuration
 * @returns Revocation status of the certificate and additional information if available
 * @throws Error if the certificate could not be retrieved or the OCSP request failed
 * @throws AbortError if the request timed out
 */
export async function getCertStatusByDomain(domain: string, config?: OCSPStatusConfig) {
    let timeout = 6000;
    if (config && typeof config.timeout === 'number') {
        timeout = config.timeout;
    }
    return getCertStatus(await downloadCert(domain, timeout), config);
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

export { downloadCert };
