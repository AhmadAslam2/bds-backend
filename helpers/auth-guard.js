const jwt = require("jsonwebtoken");
const authGuard = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res.status(401).send({
      message: "Forbidden",
    });
  }
  const [, token] = authorization.split("Bearer ");
  const decode = jwt.verify(token, process.env.JWT_SECRET, {});
  if (!decode) {
    return res.status(401).send({
      message: "Forbidden",
    });
  }
  req.user = decode;
  next();
};

module.exports = authGuard;
