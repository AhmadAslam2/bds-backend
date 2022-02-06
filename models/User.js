const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true, required: true, dropDups: true },
  contactNumber: String,
  bloodGroup: String, // TODO: Need to change as ENUM
  password: { type: String, },
  donations: [String], //Ids of Donation Requests
  salt: { type: String, },
});

const User = mongoose.model("User", userSchema);

module.exports = User;
