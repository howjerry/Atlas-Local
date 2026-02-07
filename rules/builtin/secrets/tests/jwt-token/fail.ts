// JWT Token: SHOULD trigger the rule
// Pattern: string starting with eyJ...eyJ (base64 JWT header.payload)
// NOTE: This is a SAST test fixture with FAKE JWT tokens

const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QifQ.fake_signature";

const authHeader = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzNCIsInJvbGUiOiJhZG1pbiJ9.test";
