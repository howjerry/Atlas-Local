// JWT Token: should NOT trigger the rule
// Uses dynamically generated tokens or environment variables

const token = process.env.JWT_TOKEN;

const authHeader = req.headers.authorization;

const decoded = jwt.verify(token, process.env.JWT_SECRET);

// Short string starting with eyJ but not a full JWT
const partial = "eyJ";
