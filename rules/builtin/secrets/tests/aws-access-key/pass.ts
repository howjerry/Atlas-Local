// AWS Access Key: should NOT trigger the rule
// Uses environment variables or placeholders instead of hardcoded keys

const awsKey = process.env.AWS_ACCESS_KEY_ID;

const config = {
  accessKeyId: process.env.AWS_ACCESS_KEY_ID || "",
};

// Comment mentioning the format: keys start with AKIA but no actual key here
const keyPrefix = "AKIA";
