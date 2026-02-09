// 不應該被偵測：使用環境變數或 placeholder

const gitlabToken = process.env.GITLAB_TOKEN;

const apiConfig = {
  token: process.env.GITLAB_PAT || "",
};

const headers = {
  "PRIVATE-TOKEN": "glpat-YOUR_TOKEN_HERE",
};

const example = "glpat-xxx";
