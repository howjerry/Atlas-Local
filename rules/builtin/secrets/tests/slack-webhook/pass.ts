// 不應該被偵測：使用環境變數或 placeholder

const webhookUrl = process.env.SLACK_WEBHOOK_URL;

const slackConfig = {
  url: process.env.SLACK_WEBHOOK || "",
};

const notifySlack = async (message: string) => {
  const url = process.env.SLACK_WEBHOOK_URL || "";
  await fetch(url);
};

const example = "https://hooks.slack.com/services/YOUR_WORKSPACE/YOUR_CHANNEL/YOUR_TOKEN";
