const path = require("path");
const bcrypt = require("bcrypt");
const multer = require("multer");
const express = require("express");

const User = require("../models/User");
const authGuard = require("../helpers/auth-guard");
const assignToken = require("../helpers/jwt-helper");
const DonationRequest = require("../models/DonationRequest");

const options = multer.diskStorage({
  destination: "./public/data/uploads/",
  filename: function (req, file, cb) {
    cb(
      null,
      (Math.random().toString(36) + "00000000000000000").slice(2, 10) +
      Date.now() +
      path.extname(file.originalname)
    );
  },
});
const upload = multer({ storage: options });

const router = express.Router();

router.post("/signin", async function (req, res) {
  try {
    const { email, password } = req.body;
    if (!email && !password) {
      return res.status(403).send({
        message: "Invalid params",
      });
    }

    const user = await User.findOne({ email: email });
    if (!user) {
      return res.status(403).send({
        message: "Invalid email and password combination.",
      });
    }
    const hashedPassword = await bcrypt.hash(password, user.salt);

    if (hashedPassword === user.password) {
      const token = assignToken({ email: user.email, _id: user._id });
      res.status(200).send({
        message: "Singed in successfully!",
        token,
      });
    } else {
      return res.status(403).send({
        message: "Invalid email and password combination.",
      });
    }
  } catch (error) {
    return res.status(500).send(error);
  }
});

router.post("/signup", async function (req, res) {
  try {
    const payload = req.body;
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(payload.password, salt);
    const user = await User.create({ ...payload, password: hash, salt });
    const token = assignToken({ email: user.email, _id: user._id });
    res.status(200).send({
      message: "User registerd Successfully",
      token: token,
    });
  } catch (error) {
    console.log(error)
    if (error.name === 'MongoError' && error.code === 11000) {
      return res.status(500).send({
        message: "Email already exists"
      });

    }
    return res.status(500).send(error);
  }
});

router.get("/me", authGuard, async function (req, res) {
  try {
    const { _id } = req.user;
    const user = await User.findById(_id);
    res.status(200).send({
      user,
    });
  } catch (error) {
    return res.status(500).send(error);
  }
});

router.get("/donationRequests", async function (req, res, next) {
  const donationRequests = await DonationRequest.find();
  return res.status(200).send({
    donationRequests,
  });
});

router.post(
  "/post/donationRequest",
  authGuard,
  async function (req, res,) {
    try {
      const payload = req.body;
      await DonationRequest.create({ ...payload, userId: req.user._id });
      res.status(200).send({
        message: "Request submitted successfully!",
      });
    } catch (error) {
      console.log(error);
    }
  }
);

router.put(
  "/confirm/donationRequest/:id",
  authGuard,
  async function (req, res) {
    try {
      const { _id: userId } = req.user
      const { id: requestId } = req.params;
      const _donationRuquest = await DonationRequest.findById(requestId);
      if (!_donationRuquest) {
        return res.status(403).send({
          message: "Donation with the given id is not available"
        })
      }
      await DonationRequest.findByIdAndUpdate(requestId,
        { $inc: { amountFilled: +1 } }
      );
      await User.findByIdAndUpdate(userId, {
        $push: { donations: _donationRuquest._id }
      },
        { new: true, });
      return res.status(200).send({
        message: "Successfully accepted!",
      });
    } catch (error) {
      console.log(error);
      return res.status(500).send({
        message: "Something went wrong please contact customer support at support@bds.com",
      });
    }
  }
);

/* GET donation request for the loggedin users. */
router.get("/my/donationRequests", authGuard, async function (req, res) {
  const { _id } = req.user;
  const donationRequests = await DonationRequest.find({
    userId: _id,
  });
  return res.status(200).send({
    donationRequests,
  });
});

/* GET donation for the loggedin user. */
router.get("/my/donations", authGuard, async function (req, res) {
  const { donations: donationIds } = req.user;
  const donations = await DonationRequest.find({
    userId: {
      $in: [...donationIds]
    },
  });
  return res.status(200).send({
    donations,
  });
});

module.exports = router;
