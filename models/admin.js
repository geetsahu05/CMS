const mongoose = require("mongoose")

mongoose.connect("mongodb://127.0.0.1:27017/CMS");

const AdminSchema = new mongoose.Schema({

    name: String,
    email: String,
    password: String


})

const AdminModel = mongoose.model('admin' , AdminSchema)
module.exports = AdminModel