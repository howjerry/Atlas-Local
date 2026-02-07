// Test fixture: safe code that should NOT trigger secrets detection.
// These are legitimate code patterns that look similar to secrets but are not.

// Environment variable references (not hardcoded secrets)
const apiKey = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;
const token = process.env.GITHUB_TOKEN;

// Short strings (below entropy threshold)
const name = "John";
const greeting = "Hello, World!";

// Placeholder values (common in documentation)
const example = "YOUR_API_KEY_HERE";
const placeholder = "<INSERT_TOKEN>";

// Normal connection strings without passwords
const readOnlyUrl = "postgresql://readonly@db.example.com:5432/mydb";

// Normal code identifiers
const maxRetries = 5;
const isAuthenticated = false;
const userAgent = "Mozilla/5.0 (compatible; Atlas/1.0)";

export { apiKey, dbUrl, token, name, greeting, example, placeholder, readOnlyUrl };
