const mongoose = require("mongoose")
require("dotenv").config(); 

mongoose.connect(process.env.MONGODB_ALTAS_LINK);

const AdminSchema = new mongoose.Schema({
    name: String,
    email: { type: String, required: true, unique: true },
    password: String, // keep for local login
    googleId: { type: String, unique: true, sparse: true }, // allow null for non-Google users
    picture: String,
    authProvider: { type: String, enum: ["local", "google"], default: "local" }
});

const AdminModel = mongoose.model("admin", AdminSchema);
module.exports = AdminModel;
