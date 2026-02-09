// 不應該被偵測：使用環境變數或 placeholder

const sendgridKey = process.env.SENDGRID_API_KEY;

const emailConfig = {
  apiKey: process.env.SENDGRID_API_KEY || "",
};

const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const example = "SG.YOUR_API_KEY.YOUR_SECRET";
