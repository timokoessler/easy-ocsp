import { X509Certificate } from 'node:crypto';
import * as pkijs from 'pkijs';
import { convertToPkijsCert, derToCert } from './convert';
import { buildOCSPRequest, getCAInfoUrls, parseOCSPResponse } from './ocsp';
import { getCertificateByHost } from './tls';

export type SupportedCertType = string | Buffer | X509Certificate | pkijs.Certificate;

async function downloadIssuerCert(cert: SupportedCertType): Promise<Buffer> {
    const { issuerUrl } = getCAInfoUrls(convertToPkijsCert(cert));
    const res = await fetch(issuerUrl);
    if (!res.ok) {
        throw new Error(`Issuer certificate download failed with status ${res.status} ${res.statusText} ${issuerUrl}`);
    }
    return Buffer.from(await res.arrayBuffer());
}

/**
 * Get the status of a certificate
 * @param cert string | Buffer | X509Certificate | pkijs.Certificate
 * @param issuerCert string | Buffer | X509Certificate | pkijs.Certificate
 * @returns 0 = good, 1 = revoked, 2 = unknown
 */
export async function getCertStatus(cert: SupportedCertType, issuerCert?: SupportedCertType) {
    const certificate = convertToPkijsCert(cert);
    let issuerCertificate: pkijs.Certificate;
    if (!issuerCert) {
        issuerCertificate = derToCert(await downloadIssuerCert(certificate));
    } else {
        issuerCertificate = convertToPkijsCert(issuerCert);
    }

    const { ocspUrl } = getCAInfoUrls(certificate);
    const ocspRequestBody = await buildOCSPRequest(certificate, issuerCertificate);

    const res = await fetch(ocspUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/ocsp-request',
        },
        body: Buffer.from(ocspRequestBody),
    });

    if (!res.ok) {
        throw new Error(`OCSP request failed with status ${res.status} ${res.statusText}`);
    }
    const responseData = Buffer.from(await res.arrayBuffer());
    return parseOCSPResponse(responseData, certificate, issuerCertificate);
}

export async function getCertStatusByDomain(domain: string) {
    return getCertStatus(await getCertificateByHost(domain));
}
