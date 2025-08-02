import { webcrypto } from 'node:crypto';
import { Constructed, Enumerated, GeneralizedTime, OctetString, UTCTime } from 'asn1js';
import * as pkijs from 'pkijs';
import type { OCSPStatusConfig, OCSPStatusResponse } from './index';
import { convertToPkijsCert, typedArrayToBuffer } from './convert';

const cryptoEngine = new pkijs.CryptoEngine({
    crypto: webcrypto as Crypto,
});
pkijs.setEngine('crypto', cryptoEngine as pkijs.ICryptoEngine);

export async function buildOCSPRequest(cert: pkijs.Certificate, issuerCert: pkijs.Certificate, config: OCSPStatusConfig) {
    const ocspReq = new pkijs.OCSPRequest();

    await ocspReq.createForCertificate(cert, {
        hashAlgorithm: 'SHA-1',
        issuerCertificate: issuerCert,
    });

    let nonce: ArrayBuffer | null = null;
    if (config.enableNonce) {
        nonce = new OctetString({
            valueHex: pkijs.getRandomValues(new Uint8Array(32)),
        }).toBER();
        ocspReq.tbsRequest.requestExtensions = [
            new pkijs.Extension({
                extnID: '1.3.6.1.5.5.7.48.1.2', // nonce
                extnValue: nonce,
            }),
        ];
    }
    return {
        ocspReq: ocspReq.toSchema(true).toBER(),
        nonce,
    };
}

type AccessDescription = {
    accessMethod: string;
    accessLocation: { type: number; value: string };
};

export function getCAInfoUrls(cert: pkijs.Certificate): { ocspUrl: string; issuerUrl: string } {
    if (!cert.extensions) {
        throw new Error('Certificate does not contain any extensions');
    }
    const authorityInfoAccessExtension = cert.extensions.find((ext) => ext.extnID === '1.3.6.1.5.5.7.1.1');
    if (
        !authorityInfoAccessExtension ||
        !authorityInfoAccessExtension.parsedValue ||
        !authorityInfoAccessExtension.parsedValue.accessDescriptions
    ) {
        throw new Error('Certificate does not contain authority information access extension');
    }
    const ocsp = authorityInfoAccessExtension.parsedValue.accessDescriptions.find(
        (ext: AccessDescription) => ext.accessMethod === '1.3.6.1.5.5.7.48.1',
    );
    if (!ocsp || !ocsp.accessLocation || !ocsp.accessLocation.value) {
        throw new Error('Certificate does not contain OCSP url');
    }
    const issuer = authorityInfoAccessExtension.parsedValue.accessDescriptions.find(
        (ext: AccessDescription) => ext.accessMethod === '1.3.6.1.5.5.7.48.2',
    );
    if (!issuer || !issuer.accessLocation || !issuer.accessLocation.value) {
        throw new Error('Certificate does not contain issuer url');
    }

    return {
        ocspUrl: ocsp.accessLocation.value,
        issuerUrl: issuer.accessLocation.value,
    };
}

/**
 * Parse a raw OCSP response and return the status of the certificate.
 * @param responseData The raw OCSP response data as a Buffer.
 * @param certificate The certificate to check the status for.
 * @param issuerCertificate The issuer certificate of the certificate to check.
 * @param config Additional configuration options, see {@link OCSPStatusConfig}.
 * @param nonce The nonce used in the OCSP request.
 * @returns The parsed OCSP response.
 */
export async function parseOCSPResponse(
    responseData: ArrayBuffer,
    certificate: pkijs.Certificate,
    issuerCertificate: pkijs.Certificate,
    config: OCSPStatusConfig,
    nonce: ArrayBuffer | null,
): Promise<OCSPStatusResponse> {
    const ocspResponse = pkijs.OCSPResponse.fromBER(responseData);

    const responseCode = ocspResponse.responseStatus.valueBlock.valueDec;
    if (responseCode !== 0) {
        switch (responseCode) {
            case 1:
                throw new Error('OCSP server response: malformedRequest');
            case 2:
                throw new Error('OCSP server response: internalError');
            case 3:
                throw new Error('OCSP server response: tryLater');
            case 5:
                throw new Error('OCSP server response: sigRequired');
            case 6:
                throw new Error('OCSP server response: unauthorized');
            default:
                throw new Error('OCSP server response: unknown');
        }
    }

    if (!ocspResponse.responseBytes) {
        throw new Error('OCSP server response does not contain response bytes');
    }

    if (ocspResponse.responseBytes.responseType !== '1.3.6.1.5.5.7.48.1.1') {
        throw new Error('Unknown ocsp response type');
    }

    const basicResponse = pkijs.BasicOCSPResponse.fromBER(typedArrayToBuffer(ocspResponse.responseBytes.response.valueBlock.valueHexView));
    if (!Array.isArray(basicResponse.tbsResponseData.responses)) {
        throw new Error('OCSP response does not contain any response data');
    }

    if (basicResponse.tbsResponseData.responses.length !== 1) {
        throw new Error('OCSP response does not contain exactly one response');
    }

    if (!(basicResponse.tbsResponseData.responses[0] instanceof pkijs.SingleResponse)) {
        throw new Error('OCSP response is not a pkijs.SingleResponse');
    }

    const cryptoEngine = pkijs.getEngine();
    if (!cryptoEngine || !cryptoEngine.crypto) {
        throw new Error('No pkijs crypto engine');
    }

    if (config.validateSignature) {
        if (!(await verifySignature(basicResponse, issuerCertificate, nonce, config, cryptoEngine))) {
            throw new Error('OCSP response signature verification failed');
        }
    }

    const singleResponse = basicResponse.tbsResponseData.responses[0];

    const hashAlgorithm = cryptoEngine.crypto.getAlgorithmByOID(
        singleResponse.certID.hashAlgorithm.algorithmId,
        true,
        'CertID.hashAlgorithm',
    );

    const certID = new pkijs.CertID();
    await certID.createForCertificate(
        certificate,
        {
            hashAlgorithm: hashAlgorithm.name,
            issuerCertificate,
        },
        cryptoEngine.crypto,
    );

    if (!singleResponse.certID.isEqual(certID)) {
        throw new Error('OCSP response does not match certificate');
    }

    let status: 'good' | 'revoked' | 'unknown' = 'unknown';

    if (singleResponse.certStatus.idBlock.isConstructed) {
        if (singleResponse.certStatus.idBlock.tagNumber === 1) {
            status = 'revoked';
        }
    } else {
        if (singleResponse.certStatus.idBlock.tagNumber === 0) {
            status = 'good';
        } else if (singleResponse.certStatus.idBlock.tagNumber !== 2) {
            throw new Error(`OCSP response certStatus is not good, revoked or unknown: ${singleResponse.certStatus.idBlock.tagNumber}`);
        }
    }

    const result: OCSPStatusResponse = {
        status: status,
        ocspUrl: config.ocspUrl as string,
    };

    if (basicResponse.tbsResponseData.producedAt instanceof Date) {
        result.producedAt = basicResponse.tbsResponseData.producedAt;
    }

    if (singleResponse.nextUpdate instanceof Date) {
        result.nextUpdate = singleResponse.nextUpdate;
    }

    if (singleResponse.thisUpdate instanceof Date) {
        result.thisUpdate = singleResponse.thisUpdate;
    }

    if (status === 'revoked' && Array.isArray(singleResponse.certStatus?.valueBlock?.value)) {
        for (const v of singleResponse.certStatus.valueBlock.value) {
            if (v instanceof GeneralizedTime) {
                result.revocationTime = v.toDate();
            }
            if (v instanceof UTCTime) {
                result.revocationTime = v.toDate();
            }
            if (v instanceof Constructed) {
                if (Array.isArray(v.valueBlock.value) && v.valueBlock.value.length === 1) {
                    const vBlock = v.valueBlock.value[0];
                    if (vBlock instanceof Enumerated) {
                        result.revocationReason = vBlock.valueBlock.valueDec;
                    }
                }
            }
        }
    }

    if (config.rawResponse === true) {
        result.rawResponse = Buffer.from(responseData);
    }

    return result;
}

async function verifySignature(
    basicOcspResponse: pkijs.BasicOCSPResponse,
    trustedCert: pkijs.Certificate,
    nonce: ArrayBuffer | null,
    config: OCSPStatusConfig,
    cryptoEngine = pkijs.getEngine(),
) {
    let signatureCert: pkijs.Certificate | null = null;

    if (!cryptoEngine || !cryptoEngine.crypto) {
        throw new Error('No pkijs crypto engine');
    }

    if (config.ocspCertificate) {
        signatureCert = convertToPkijsCert(config.ocspCertificate);
    } else if (basicOcspResponse.tbsResponseData.responderID instanceof pkijs.RelativeDistinguishedNames) {
        if (trustedCert.subject.isEqual(basicOcspResponse.tbsResponseData.responderID)) {
            signatureCert = trustedCert;
        }
    } else if (basicOcspResponse.tbsResponseData.responderID instanceof OctetString) {
        const hash = await webcrypto.subtle.digest(
            { name: 'sha-1' },
            trustedCert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
        );
        if (Buffer.compare(Buffer.from(hash), basicOcspResponse.tbsResponseData.responderID.valueBlock.valueHexView) === 0) {
            signatureCert = trustedCert;
        }
    } else {
        throw new Error('Responder ID is unknown');
    }

    if (!signatureCert) {
        if (!Array.isArray(basicOcspResponse.certs) || !basicOcspResponse.certs.length) {
            throw new Error('OCSP response is not signed by trusted certificate and does not contain additional certificates');
        }
        for (const cert of basicOcspResponse.certs) {
            if (basicOcspResponse.tbsResponseData.responderID instanceof pkijs.RelativeDistinguishedNames) {
                if (cert.subject.isEqual(basicOcspResponse.tbsResponseData.responderID)) {
                    signatureCert = cert;
                    break;
                }
            } else if (basicOcspResponse.tbsResponseData.responderID instanceof OctetString) {
                const hash = await webcrypto.subtle.digest(
                    { name: 'sha-1' },
                    cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
                );
                if (Buffer.compare(Buffer.from(hash), basicOcspResponse.tbsResponseData.responderID.valueBlock.valueHexView) === 0) {
                    signatureCert = cert;
                }
            }
        }

        if (!signatureCert) {
            throw new Error('OCSP response is not signed by trusted certificate or additional response certificates');
        }

        const chain = new pkijs.CertificateChainValidationEngine({
            certs: basicOcspResponse.certs,
            trustedCerts: [trustedCert],
        });
        const verificationResult = await chain.verify({}, cryptoEngine.crypto);
        if (!verificationResult.result) {
            throw new Error('Validation of OCSP response certificate chain failed');
        }
    }

    // RFC 8954
    if (config.enableNonce && nonce && Array.isArray(basicOcspResponse.tbsResponseData.responseExtensions)) {
        const nonceExtension = basicOcspResponse.tbsResponseData.responseExtensions.find((e) => e.extnID === '1.3.6.1.5.5.7.48.1.2');
        if (nonceExtension && Buffer.compare(Buffer.from(nonce), nonceExtension.extnValue.valueBlock.valueHexView) !== 0) {
            throw new Error('OCSP response nonce does not match request nonce');
        }
    }

    return cryptoEngine.crypto.verifyWithPublicKey(
        typedArrayToBuffer(basicOcspResponse.tbsResponseData.tbsView),
        basicOcspResponse.signature,
        signatureCert.subjectPublicKeyInfo,
        basicOcspResponse.signatureAlgorithm,
    );
}
