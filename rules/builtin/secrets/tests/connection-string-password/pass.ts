// Connection String Password: should NOT trigger the rule
// Uses environment variables or connection strings without embedded passwords

const dbUrl = process.env.DATABASE_URL;

const mongoUri = process.env.MONGO_URI;

// URL without password
const apiUrl = "https://api.example.com:8080/v1/data";

// URL with short password placeholder (less than 4 chars)
const testUrl = "http://user:xx@localhost";
