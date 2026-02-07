// Google API Key: should NOT trigger the rule
// Uses environment variables or placeholders

const googleKey = process.env.GOOGLE_API_KEY;

const mapsKey = process.env.GOOGLE_MAPS_KEY || "";

// Short prefix only, not a full key
const prefix = "AIza";

const config = {
  apiKey: process.env.GOOGLE_API_KEY,
};
