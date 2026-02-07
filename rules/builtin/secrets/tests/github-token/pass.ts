// GitHub Token: should NOT trigger the rule
// Uses environment variables or placeholders instead of hardcoded tokens

const token = process.env.GITHUB_TOKEN;

const config = {
  githubToken: process.env.GH_TOKEN || "",
};

// Short prefix only, not a full token
const prefix = "ghp_";
