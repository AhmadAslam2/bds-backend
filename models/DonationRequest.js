const mongoose = require("mongoose");

const donationRequestSchema = new mongoose.Schema({
    userId: String,
    description: String,
    bloodType: String,
    status: String,
    location: String,
    amountNeeded: Number,
    amountFilled: { type: Number, default: 0 },
    diagnosis: String
});

const DonationRequest = mongoose.model("DonationRequest", donationRequestSchema);

module.exports = DonationRequest;
