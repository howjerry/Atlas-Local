// 應該被偵測：包含 Slack Webhook URL 的字串
// NOTE: 這些是 SAST 測試用假 URL，不是真實 webhook

const webhookUrl = "https://hooks.slack.com/services/T00000000/B00000000/00000000000000000000";

const slackConfig = {
  url: "https://hooks.slack.com/services/T00000000/B00000000/00000000000000000000",
};

const notifySlack = async (message: string) => {
  await fetch("https://hooks.slack.com/services/T00000000/B00000000/00000000000000000000");
};
