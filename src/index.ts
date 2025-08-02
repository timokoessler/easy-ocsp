import type { X509Certificate } from 'node:crypto';
import * as pkijs from 'pkijs';
import { convertPkijsCertToPem, convertToPkijsCert } from './convert';
import { buildOCSPRequest, getCAInfoUrls, parseOCSPResponse } from './ocsp';
import { downloadCert } from './tls';
import { OCSPStatusConfig, OCSPStatusResponse, OCSPRevocationReason } from './types';
import { fetchWrapper } from 'fetchWrapper';

/**
 * Function to download and parse the certificate of the issuer of a certificate
 * This function is used internally to download the issuer certificate if it is not provided in the config
 * Its exported for convenience if you want to download the issuer certificate manually for some reason
 * @param cert The certificate to download the issuer certificate for, can be a PEM encoded string, X509Certificate object, pkijs.Certificate or the raw certificate as Buffer or ArrayBuffer
 * @param timeout Optional timeout in milliseconds for the request. Default is 6000ms
 * @returns A pkijs.Certificate object of the issuer certificate
 */
export async function downloadIssuerCert(
    cert: string | Buffer | X509Certificate | pkijs.Certificate | ArrayBuffer,
    timeout?: number,
): Promise<pkijs.Certificate> {
    let _timeoutMs = defaultConfig.timeout;
    if (typeof timeout === 'number') {
        _timeoutMs = timeout;
    }
    const { issuerUrl } = getCAInfoUrls(convertToPkijsCert(cert));
    const res = await fetchWrapper(issuerUrl, {}, _timeoutMs, `Failed to download issuer certificate`);
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

const defaultConfig = {
    validateSignature: true,
    enableNonce: true,
    timeout: 6000,
} satisfies OCSPStatusConfig;

/**
 * Internal function to send an OCSP request and return the response
 * @param cert The certificate to check, as PEM encoded string, X509Certificate object, pkijs.Certificate or the raw certificate as Buffer or ArrayBuffer
 * @param config Additional configuration
 * @returns The OCSP response as a buffer, the certificate and the issuer certificate and the nonce
 */
async function sendOCSPRequest(cert: string | Buffer | X509Certificate | pkijs.Certificate | ArrayBuffer, config: OCSPStatusConfig) {
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

    const res = await fetchWrapper(
        config.ocspUrl,
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/ocsp-request',
            },
            body: ocspReq,
        },
        config.timeout ?? defaultConfig.timeout,
        'Failed to send OCSP request',
    );

    if (!res.ok) {
        throw new Error(`OCSP request failed with http status ${res.status} ${res.statusText}`);
    }

    return {
        response: await res.arrayBuffer(),
        certificate,
        issuerCertificate,
        nonce,
    };
}

/**
 * Get the revocation status of a certificate.
 * @param cert The certificate to check, as PEM encoded string, X509Certificate object, pkijs.Certificate or the raw certificate as Buffer or ArrayBuffer
 * @param config Provide optional additional configuration
 * @returns Revocation status of the certificate and additional information if available
 * @throws Error if the OCSP request failed
 * @throws AbortError if the request timed out
 */
export async function getCertStatus(
    cert: string | Buffer | X509Certificate | pkijs.Certificate | ArrayBuffer,
    config?: OCSPStatusConfig,
): Promise<OCSPStatusResponse> {
    const _config = { ...defaultConfig, ...config };

    const { response, certificate, issuerCertificate, nonce } = await sendOCSPRequest(cert, _config);
    return parseOCSPResponse(response, certificate, issuerCertificate, _config, nonce);
}

/**
 * Download the tls certificate that is used for a domain and check its revocation status. This is a convenience function that combines downloadCert and getCertStatus
 * @param domain Domain to check the certificate for (e.g. 'github.com')
 * @param config Provide optional additional configuration
 * @returns Revocation status of the certificate and additional information if available
 * @throws Error if the certificate could not be retrieved or the OCSP request failed
 * @throws AbortError if the request timed out
 */
export async function getCertStatusByDomain(domain: string, config?: OCSPStatusConfig): Promise<OCSPStatusResponse> {
    let _domain = domain;
    let timeout = 6000;
    if (config && typeof config.timeout === 'number') {
        timeout = config.timeout;
    }
    if (_domain.includes('/')) {
        try {
            const url = new URL(_domain);
            _domain = url.hostname;
        } catch {
            throw new Error('Invalid URL');
        }
    }
    return getCertStatus(await downloadCert(_domain, timeout), config);
}

/**
 * Get raw (binary) OCSP response for a certificate
 * The response is not parsed or validated.
 * @param cert The certificate to check, as PEM encoded string, X509Certificate object, pkijs.Certificate or the raw certificate as Buffer or ArrayBuffer
 * @param config Provide optional additional configuration
 * @returns The raw OCSP response as a buffer, the nonce and the pem encoded issuer certificate
 */
export async function getRawOCSPResponse(
    cert: string | Buffer | X509Certificate | pkijs.Certificate | ArrayBuffer,
    config?: OCSPStatusConfig,
) {
    const _config = { ...defaultConfig, ...config };

    const { response, issuerCertificate, nonce } = await sendOCSPRequest(cert, _config);

    return {
        rawResponse: Buffer.from(response),
        nonce: nonce ? Buffer.from(nonce) : undefined,
        issuerCert: convertPkijsCertToPem(issuerCertificate),
    };
}

/**
 * Get the OCSP and issuer URLs from a certificate
 * @param cert The certificate to check, as PEM encoded string, X509Certificate object, pkijs.Certificate or the raw certificate as Buffer or ArrayBuffer
 * @returns OCSP and issuer URLs
 * @throws Error if the certificate does not contain the required information
 */
export function getCertURLs(cert: string | Buffer | X509Certificate | pkijs.Certificate | ArrayBuffer): {
    ocspUrl: string;
    issuerUrl: string;
} {
    return getCAInfoUrls(convertToPkijsCert(cert));
}

export { downloadCert, parseOCSPResponse, OCSPRevocationReason, convertToPkijsCert, convertPkijsCertToPem };
export type { OCSPStatusConfig, OCSPStatusResponse };
