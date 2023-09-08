import { readFile } from 'fs/promises';

export async function readCertFile(name: string) {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    return readFile(`${__dirname}/certs/${name}.pem`, 'ascii');
}
