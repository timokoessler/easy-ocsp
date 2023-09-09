import { webcrypto } from 'node:crypto';
import { GeneralizedTime, OctetString, UTCTime } from 'asn1js';
import * as pkijs from 'pkijs';
import { OCSPStatusConfig } from 'index';

const cryptoEngine = new pkijs.CryptoEngine({
    crypto: webcrypto as Crypto,
});
pkijs.setEngine('crypto', cryptoEngine);

export async function buildOCSPRequest(cert: pkijs.Certificate, issuerCert: pkijs.Certificate) {
    const ocspReq = new pkijs.OCSPRequest();

    await ocspReq.createForCertificate(cert, {
        hashAlgorithm: 'SHA-1',
        issuerCertificate: issuerCert,
    });

    const nonce = pkijs.getRandomValues(new Uint8Array(10));
    ocspReq.tbsRequest.requestExtensions = [
        new pkijs.Extension({
            extnID: '1.3.6.1.5.5.7.48.1.2', // nonce
            extnValue: new OctetString({ valueHex: nonce.buffer }).toBER(),
        }),
    ];

    return ocspReq.toSchema(true).toBER();
}

type AccessDescription = { accessMethod: string; accessLocation: { type: number; value: string } };

export function getCAInfoUrls(cert: pkijs.Certificate) {
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

function statusToString(status: number) {
    switch (status) {
        case 0:
            return 'good';
        case 1:
            return 'revoked';
        case 2:
            return 'unknown';
        default:
            throw new Error('Unknown certificate status');
    }
}

export async function parseOCSPResponse(
    responseData: Buffer,
    certificate: pkijs.Certificate,
    issuerCertificate: pkijs.Certificate,
    config: OCSPStatusConfig,
) {
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

    const basicResponse = pkijs.BasicOCSPResponse.fromBER(ocspResponse.responseBytes.response.valueBlock.valueHexView);

    if (config.validateSignature) {
        if (!(await verifySignature(basicResponse, issuerCertificate))) {
            throw new Error('OCSP response signature verification failed');
        }
    }

    if (basicResponse.tbsResponseData.responses.length !== 1) {
        throw new Error('OCSP response does not contain exactly one response');
    }

    const status = await ocspResponse.getCertificateStatus(certificate, issuerCertificate);
    if (!status.isForCertificate) {
        throw new Error('OCSP response does not contain status for correct certificate');
    }

    const result: {
        status: 'good' | 'revoked' | 'unknown';
        revocationTime?: Date;
    } = {
        status: statusToString(status.status),
    };

    if (status.status === 1 && Array.isArray(basicResponse.tbsResponseData.responses[0]?.certStatus?.valueBlock?.value)) {
        for (const v of basicResponse.tbsResponseData.responses[0].certStatus.valueBlock.value) {
            if (v instanceof GeneralizedTime) {
                result.revocationTime = v.toDate();
                break;
            }
            if (v instanceof UTCTime) {
                result.revocationTime = v.toDate();
                break;
            }
        }
    }
    return result;
}

async function verifySignature(basicOcspResponse: pkijs.BasicOCSPResponse, trustedCert: pkijs.Certificate) {
    let signatureCert: pkijs.Certificate | null = null;

    if (basicOcspResponse.tbsResponseData.responderID instanceof pkijs.RelativeDistinguishedNames) {
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

    const cryptoEngine = pkijs.getEngine();
    if (!cryptoEngine || !cryptoEngine.crypto) {
        throw new Error('No crypto engine');
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

    return cryptoEngine.crypto.verifyWithPublicKey(
        basicOcspResponse.tbsResponseData.tbsView,
        basicOcspResponse.signature,
        signatureCert!.subjectPublicKeyInfo,
        basicOcspResponse.signatureAlgorithm,
    );
}
