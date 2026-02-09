// 應該被偵測：hardcoded JWT secret 在變數宣告中

const jwt_secret = "my-super-secret-key-12345";

const jwtSecret = "hardcoded-secret-value";

const TOKEN_SECRET = "another-hardcoded-secret";

const config = {
  jwt_secret: "embedded-secret",
};

let tokenSecret = "yet-another-secret";
