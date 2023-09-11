import { connect as tlsConnect, ConnectionOptions } from 'node:tls';

/**
 * Get a TLS certificate by hostname. This function will always connect to port 443.
 * @param hostname Hostname to connect to (e.g. 'github.com')
 * @returns Buffer containing the raw certificate (DER)
 */
export function downloadCert(hostname: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const options: ConnectionOptions = {
            port: 443,
            host: hostname,
            servername: hostname,
            timeout: 3000,
        };
        const socket = tlsConnect(options, () => {
            const cert = socket.getPeerCertificate();
            if (!cert || !cert.raw) {
                reject(new Error(`No certificate found for host ${hostname}`));
            }
            resolve(cert.raw);
            socket.end();
        });
        socket.on('error', (err) => {
            reject(err);
        });
        socket.on('timeout', () => {
            reject(new Error(`Timeout while connecting to host ${hostname}`));
        });
    });
}
