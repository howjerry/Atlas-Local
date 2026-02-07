// Generic API Key: should NOT trigger the rule
// Uses environment variables or non-sensitive variable names

const apiKey = process.env.API_KEY;

const secret = process.env.APP_SECRET;

const dbHost = "localhost";

const maxRetries = "3";

const appName = "my-cool-app";
