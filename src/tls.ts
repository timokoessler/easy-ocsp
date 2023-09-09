import { connect as tlsConnect, TLSSocket, ConnectionOptions } from 'tls';

/**
 * Get TLS certificate by hostname (port 443)
 * @param hostname
 * @returns Buffer containing the raw certificate
 */
export function getCertificateByHost(hostname: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const options: ConnectionOptions = {
            port: 443,
            host: hostname,
            servername: hostname,
        };
        const socket: TLSSocket = tlsConnect(options, () => {
            const cert = socket.getPeerCertificate();
            if (!cert) {
                reject(new Error('No certificate found'));
            } else {
                resolve(cert.raw);
            }
            socket.end();
        });
        socket.on('error', (err) => {
            reject(err);
        });
    });
}
