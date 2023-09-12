/** @type {import('jest').Config} */
export default {
    testEnvironment: 'node',
    transform: {
        '^.+\\.(t|j)sx?$': '@swc/jest',
    },
    collectCoverage: true,
    collectCoverageFrom: ['src/**/*.ts'],
    testTimeout: 10000,
    coverageDirectory: 'coverage',
    forceExit: true,
};
