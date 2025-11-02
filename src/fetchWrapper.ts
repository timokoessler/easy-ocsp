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

        let causeText = '';
        if ('cause' in error && error.cause) {
            if (typeof error.cause === 'string') {
                causeText = error.cause;
            } else if (error.cause instanceof Error) {
                causeText = error.cause.message;
            } else {
                try {
                    causeText = JSON.stringify(error.cause);
                } catch {
                    // oxlint-disable-next-line no-base-to-string
                    causeText = String(error.cause);
                }
            }
        }

        throw new Error(`${errorPrefix}: ${error.message}${causeText ? ` (${causeText})` : ''}`);
    } finally {
        clearTimeout(timeoutId);
    }
}
