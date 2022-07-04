const crypto = require("crypto");
require("dotenv").config();

const PRIVATEKEY = process.env.PRIVATE_KEY;

const calculateToken = (userEmail = "") => {
  return crypto
    .createHash("md5")
    .update(userEmail + PRIVATEKEY)
    .digest("HEX");
};

module.exports = { calculateToken };
