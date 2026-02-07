// Google API Key: SHOULD trigger the rule
// Pattern: string starting with AIza followed by 30+ alphanumeric/dash/underscore chars
// NOTE: This is a SAST test fixture with FAKE Google API keys

const googleKey = "AIzaSyA1234567890abcdefghijklmnopqrstuv";

const mapsKey = "AIzaSyBCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

const config = {
  apiKey: "AIzaSyCFAKEKEY12345678901234567890fake",
};
