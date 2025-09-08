const mongoose = require("mongoose");

const BCSchema = new mongoose.Schema({
    name: String,
    email: { type: String, required: true, unique: true },
    password: String,
    googleId: { type: String, unique: true, sparse: true },
    picture: String,
    authProvider: { type: String, enum: ["local", "google"], default: "local" },
    Booked_rooms: [{ type: mongoose.Schema.ObjectId, ref: "room" }]
});

const BCModel = mongoose.model("BC", BCSchema);
module.exports = BCModel;
