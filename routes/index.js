var express = require("express");
var router = express.Router();

/* GET home page. */
router.get("/", function (req, res, next) {
  response.sendFile(path.join(__dirname, `/frontend/build/index.html`));
});

module.exports = router;
