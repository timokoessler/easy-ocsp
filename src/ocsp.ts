import { webcrypto } from 'node:crypto';
import { GeneralizedTime, OctetString } from 'asn1js';
import * as pkijs from 'pkijs';

const cryptoEngine = new pkijs.CryptoEngine({
    crypto: webcrypto as Crypto,
});
pkijs.setEngine('crypto', cryptoEngine);

export async function buildOCSPRequest(cert: pkijs.Certificate, issuerCert: pkijs.Certificate) {
    const ocspReq = new pkijs.OCSPRequest();

    if (!Array.isArray(cert.extensions)) {
        throw new Error('Certificate does not contain extensions');
    }

    const authorityKeyIdentifier = cert.extensions.find((ext) => ext.extnID === '2.5.29.35');
    if (!authorityKeyIdentifier) {
        throw new Error('Certificate does not contain authority key identifier extension');
    }

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
        throw new Error('Certificate does not contain extensions');
    }
    const authorityInformationAccessExtension = cert.extensions.find((ext) => ext.extnID === '1.3.6.1.5.5.7.1.1');
    if (
        !authorityInformationAccessExtension ||
        !authorityInformationAccessExtension.parsedValue ||
        !authorityInformationAccessExtension.parsedValue.accessDescriptions
    ) {
        throw new Error('Certificate does not contain authority information access extension');
    }
    const ocsp = authorityInformationAccessExtension.parsedValue.accessDescriptions.find((ext: AccessDescription) => ext.accessMethod === '1.3.6.1.5.5.7.48.1');
    if (!ocsp || !ocsp.accessLocation || !ocsp.accessLocation.value) {
        throw new Error('Certificate does not contain OCSP url');
    }
    const issuer = authorityInformationAccessExtension.parsedValue.accessDescriptions.find(
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

export async function parseOCSPResponse(responseData: Buffer, certificate: pkijs.Certificate, issuerCertificate: pkijs.Certificate) {
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
    const validSignature = await verifySignature(basicResponse, issuerCertificate);
    if (!validSignature) {
        throw new Error('OCSP response signature verification failed');
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
                const keys = ['year', 'month', 'day', 'hour', 'minute', 'second', 'millisecond'];
                let valid = true;
                for (const key of keys) {
                    // eslint-disable-next-line security/detect-object-injection
                    if (typeof v[key as keyof GeneralizedTime] !== 'number') {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    result.revocationTime = new Date(v.year, v.month - 1, v.day, v.hour, v.minute, v.second, v.millisecond);
                }
                break;
            }
        }
    }
    return result;
}

async function verifySignature(basicOcspResponse: pkijs.BasicOCSPResponse, trustedCert: pkijs.Certificate) {
    if (basicOcspResponse.tbsResponseData.responderID instanceof pkijs.RelativeDistinguishedNames) {
        if (!trustedCert.subject.isEqual(basicOcspResponse.tbsResponseData.responderID)) {
            throw new Error('Responder ID does not match to trusted certificate');
        }
    } else if (basicOcspResponse.tbsResponseData.responderID instanceof OctetString) {
        const hash = await webcrypto.subtle.digest({ name: 'sha-1' }, trustedCert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
        if (Buffer.compare(Buffer.from(hash), basicOcspResponse.tbsResponseData.responderID.valueBlock.valueHexView) !== 0) {
            throw new Error('Responder ID does not match to trusted certificate');
        }
    } else {
        throw new Error('Responder ID is unknown');
    }
    /* const certChain = new CertificateChainValidationEngine({
        certs: additionalCerts,
        trustedCerts,
    });
    const verificationResult = await certChain.verify({}, crypto);
    if (!verificationResult.result) {
        throw new Error("Validation of signer's certificate failed");
    } */
    const cryptoEngine = pkijs.getEngine();
    if (!cryptoEngine || !cryptoEngine.crypto) {
        throw new Error('No crypto engine');
    }
    return cryptoEngine.crypto.verifyWithPublicKey(
        basicOcspResponse.tbsResponseData.tbsView,
        basicOcspResponse.signature,
        trustedCert.subjectPublicKeyInfo,
        basicOcspResponse.signatureAlgorithm,
    );
}
