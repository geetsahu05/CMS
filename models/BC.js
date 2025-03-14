const mongoose = require("mongoose")


const BCSchema = new mongoose.Schema({

    name: String,
    email: String,
    password: String,
    Booked_rooms:[{type: mongoose.Schema.ObjectId , ref: "room"}]


})

const BCModel = mongoose.model('BC' , BCSchema)
module.exports = BCModel