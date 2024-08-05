import { readFile } from 'node:fs/promises';

export async function readCertFile(name: string) {
    return await readFile(`${__dirname}/certs/${name}.pem`, 'ascii');
}
