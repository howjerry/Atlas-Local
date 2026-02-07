// AWS Access Key: SHOULD trigger the rule
// Pattern: string starting with AKIA or ASIA followed by 12+ uppercase alphanumeric chars
// NOTE: This is a SAST test fixture with FAKE keys that match the pattern

const awsKey1 = "AKIAIOSFODNN7EXAMPLE";

const awsKey2 = "ASIAIOSFODNN7EXAMPLE";

const config = {
  accessKeyId: "AKIAI44QH8DHBEXAMPLE",
};
