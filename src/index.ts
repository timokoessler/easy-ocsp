import type { X509Certificate } from 'node:crypto';
import * as pkijs from 'pkijs';
import { convertPkijsCertToPem, convertToPkijsCert } from './convert';
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
     * The OCSP responder certificate to validate the signature of the OCSP response. If not provided issuer certificate will be used.
     */
    ocspCertificate?: string | Buffer | X509Certificate | pkijs.Certificate;
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
    /**
     * Whether to return the raw response as a buffer additionally to the parsed response. This is disabled by default.
     */
    rawResponse?: boolean;
};

/**
 * The reason why a certificate was revoked.
 * https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1
 */
export enum OCSPRevocationReason {
    unspecified = 0,
    keyCompromise = 1,
    caCompromise = 2,
    affiliationChanged = 3,
    superseded = 4,
    cessationOfOperation = 5,
    certificateHold = 6,
    removeFromCRL = 8,
    privilegeWithdrawn = 9,
    aACompromise = 10,
}

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
    /**
     * The revocation reason. Only available if the status is 'revoked' and the OCSP response contains a revocation reason.
     */
    revocationReason?: OCSPRevocationReason;
    /**
     * The raw OCSP response as a buffer. Only available if the rawResponse option is enabled in the config.
     */
    rawResponse?: Buffer;
};

/**
 * Function to download and parse the certificate of the issuer of a certificate
 * This function is used internally to download the issuer certificate if it is not provided in the config
 * Its exported for convenience if you want to download the issuer certificate manually for some reason
 * @param cert The certificate to download the issuer certificate for
 * @param timeout Optional timeout in milliseconds for the request. Default is 6000ms
 * @returns A pkijs.Certificate object of the issuer certificate
 */
export async function downloadIssuerCert(
    cert: string | Buffer | X509Certificate | pkijs.Certificate,
    timeout?: number,
): Promise<pkijs.Certificate> {
    let _timeoutMs = 6000;
    if (typeof timeout === 'number') {
        _timeoutMs = timeout;
    }
    const { issuerUrl } = getCAInfoUrls(convertToPkijsCert(cert));
    const ac = new AbortController();
    const _timeout = setTimeout(() => ac.abort(), _timeoutMs);
    const res = await fetch(issuerUrl, {
        signal: ac.signal,
    });
    clearTimeout(_timeout);
    if (!res.ok) {
        throw new Error(`Issuer certificate download failed with status ${res.status} ${res.statusText} ${issuerUrl}`);
    }

    /* Some CAs return the certificate as a DER encoded binary file.
       Others return it as a PEM encoded string (for example Microsoft).
       This is not always correctly reflected by the Content-Type header. */

    const rawResponse = Buffer.from(await res.arrayBuffer());
    try {
        return convertToPkijsCert(rawResponse);
    } catch (err) {
        if (err instanceof pkijs.AsnError) {
            const txt = rawResponse.toString('ascii');
            if (txt.includes('BEGIN CERTIFICATE')) {
                return convertToPkijsCert(txt);
            }
            throw new Error('The issuer certificate is not a valid DER or PEM encoded X.509 certificate');
        }
        throw err;
    }
}

const defaultConfig: OCSPStatusConfig = {
    validateSignature: true,
    enableNonce: true,
    timeout: 6000,
};

/**
 * Internal function to send an OCSP request and return the response
 * @param cert The certificate to check
 * @param config Additional configuration
 * @returns The OCSP response as a buffer, the certificate and the issuer certificate and the nonce
 */
async function sendOCSPRequest(cert: string | Buffer | X509Certificate | pkijs.Certificate, config: OCSPStatusConfig) {
    const certificate = convertToPkijsCert(cert);

    // Check if the certificate is expired
    if (certificate.notAfter.value.getTime() < Date.now()) {
        throw new Error('The certificate is already expired');
    }

    if (!config.ocspUrl) {
        config.ocspUrl = getCAInfoUrls(certificate).ocspUrl;
    }

    let issuerCertificate: pkijs.Certificate;
    if (!config.ca) {
        issuerCertificate = await downloadIssuerCert(certificate, config.timeout);
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

    return { response: Buffer.from(await res.arrayBuffer()), certificate, issuerCertificate, nonce };
}

/**
 * Get the revocation status of a certificate.
 * @param cert string | Buffer | X509Certificate | pkijs.Certificate
 * @param config Provide optional additional configuration
 * @returns Revocation status of the certificate and additional information if available
 * @throws Error if the OCSP request failed
 * @throws AbortError if the request timed out
 */
export async function getCertStatus(cert: string | Buffer | X509Certificate | pkijs.Certificate, config?: OCSPStatusConfig) {
    const _config = { ...defaultConfig, ...config };

    const { response, certificate, issuerCertificate, nonce } = await sendOCSPRequest(cert, _config);
    return parseOCSPResponse(response, certificate, issuerCertificate, _config, nonce);
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
    let _domain = domain;
    let timeout = 6000;
    if (config && typeof config.timeout === 'number') {
        timeout = config.timeout;
    }
    if (_domain.includes('/')) {
        try {
            const url = new URL(_domain);
            _domain = url.hostname;
        } catch (e) {
            throw new Error('Invalid URL');
        }
    }
    return getCertStatus(await downloadCert(_domain, timeout), config);
}

/**
 * Get raw (binary) OCSP response for a certificate
 * The response is not parsed or validated.
 * @param cert string | Buffer | X509Certificate | pkijs.Certificate
 * @param config Provide optional additional configuration
 * @returns The raw OCSP response as a buffer, the nonce and the pem encoded issuer certificate
 */
export async function getRawOCSPResponse(cert: string | Buffer | X509Certificate | pkijs.Certificate, config?: OCSPStatusConfig) {
    const _config = { ...defaultConfig, ...config };

    const { response, issuerCertificate, nonce } = await sendOCSPRequest(cert, _config);

    return {
        rawResponse: response,
        nonce: nonce ? Buffer.from(nonce) : undefined,
        issuerCert: convertPkijsCertToPem(issuerCertificate),
    };
}

/**
 * Get the OCSP and issuer URLs from a certificate
 * @param cert string | Buffer | X509Certificate | pkijs.Certificate
 * @returns OCSP and issuer URLs
 * @throws Error if the certificate does not contain the required information
 */
export function getCertURLs(cert: string | Buffer | X509Certificate | pkijs.Certificate): { ocspUrl: string; issuerUrl: string } {
    return getCAInfoUrls(convertToPkijsCert(cert));
}

export { downloadCert };
