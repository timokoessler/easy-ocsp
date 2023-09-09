module.exports = {
    root: true,
    parser: '@typescript-eslint/parser',
    plugins: ['@typescript-eslint'],
    env: {
        node: true,
    },
    extends: [
        'eslint:recommended',
        'plugin:@typescript-eslint/eslint-recommended',
        'plugin:@typescript-eslint/recommended',
        'plugin:security/recommended',
    ],
    rules: {
        indent: ['off', 'tab'],
        quotes: ['warn', 'single'],
        semi: ['warn', 'always'],
    },
};
