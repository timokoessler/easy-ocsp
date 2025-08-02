/**
 * Calls the original fetch function but:
 * - Adds a timeout to the request
 * - Improves the error message
 */
export async function fetchWrapper(
    url: Parameters<typeof fetch>[0],
    options: NonNullable<Parameters<typeof fetch>[1]>,
    timeout: number,
    errorPrefix: string,
): Promise<ReturnType<typeof fetch>> {
    const ac = new AbortController();
    const timeoutId = setTimeout(() => ac.abort(), timeout);

    options.signal = ac.signal;

    try {
        return await fetch(url, options);
    } catch (error) {
        if (!(error instanceof Error)) {
            throw new Error(`${errorPrefix}: ${String(error)}`);
        }
        if (error.name === 'AbortError') {
            throw new Error(`${errorPrefix}: Operation timed out after ${timeout}ms`);
        }

        throw new Error(`${errorPrefix}: ${error.message}${error.cause ? ` (${error.cause})` : ''}`);
    } finally {
        clearTimeout(timeoutId);
    }
}
