// 應該被偵測：包含 GitLab Personal Access Token 的字串
// NOTE: 這些是 SAST 測試用假 token，不是真實 key

const gitlabToken = "glpat-00000000000000000000";

const apiConfig = {
  token: "glpat-00000000000000000000000000000000000000",
};

const headers = {
  "PRIVATE-TOKEN": "glpat-00000000000000000000000000000000",
};
