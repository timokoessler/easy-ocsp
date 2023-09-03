import { webcrypto } from 'node:crypto';
import { OctetString } from 'asn1js';
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

export async function parseOCSPResponse(responseData: Buffer, certificate: pkijs.Certificate, issuerCertificate: pkijs.Certificate) {
    const ocspResponse = pkijs.OCSPResponse.fromBER(responseData);
    if (!ocspResponse.responseBytes) {
        throw new Error('OCSP response does not contain response bytes');
    }

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

    /*const verified = await ocspResponse.verify(issuerCertificate);
    if (!verified) {
        throw new Error('OCSP response verification failed');
    }*/

    const status = await ocspResponse.getCertificateStatus(certificate, issuerCertificate);

    if (!status.isForCertificate) {
        throw new Error('OCSP response is not for certificate');
    }

    return status.status;
}
