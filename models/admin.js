const mongoose = require("mongoose")
require("dotenv").config(); 

mongoose.connect(process.env.MONGODB_ALTAS_LINK);

const AdminSchema = new mongoose.Schema({

    name: String,
    email: String,
    password: String


})

const AdminModel = mongoose.model('admin' , AdminSchema)
module.exports = AdminModel