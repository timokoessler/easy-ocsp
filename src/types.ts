import type { X509Certificate } from 'node:crypto';
import type * as pkijs from 'pkijs';

/**
 * Additional optional configuration
 */
export type OCSPStatusConfig = {
    /**
     * The issuer certificate authority. If not provided, it will be downloaded from the issuer URL. If you already have the issuer certificate, you can provide it here to improve performance.
     */
    ca?: string | Buffer | X509Certificate | pkijs.Certificate | ArrayBuffer;
    /**
     * The URL of the OCSP responder. By default, it will be extracted from the certificate. If you already know the OCSP responder URL, you can provide it here.
     */
    ocspUrl?: string;
    /**
     * The OCSP responder certificate to validate the signature of the OCSP response. If not provided issuer certificate will be used.
     */
    ocspCertificate?: string | Buffer | X509Certificate | pkijs.Certificate | ArrayBuffer;
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
