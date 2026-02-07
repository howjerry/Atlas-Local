// Test fixture: example config file that should be EXCLUDED from secrets scanning.
// Files with ".example." in their name should be secrets-excluded.

const config = {
    apiKey: "AKIAIOSFODNN7EXAMPLE",
    secret: "ghp_ExampleTokenForDocumentation1234567890",
    database: "postgresql://user:password@localhost:5432/dev",
};

export default config;
