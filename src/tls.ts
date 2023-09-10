import { connect as tlsConnect, TLSSocket, ConnectionOptions } from 'node:tls';

/**
 * Get a TLS certificate by hostname. This function will always connect to port 443.
 * @param hostname Hostname to connect to (e.g. 'github.com')
 * @returns Buffer containing the raw certificate (DER)
 */
export function getCertificateByHost(hostname: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const options: ConnectionOptions = {
            port: 443,
            host: hostname,
            servername: hostname,
            timeout: 3000,
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
