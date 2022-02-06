const jwt = require("jsonwebtoken");

const assignToken = ({ email, _id }) => {
  return jwt.sign({ email, _id }, process.env.JWT_SECRET);
};

module.exports = assignToken;
