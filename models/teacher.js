const mongoose = require("mongoose")


const teacherSchema = new mongoose.Schema({

    name: String,
    email: String,
    password: String,
    Booked_rooms:[{type: mongoose.Schema.ObjectId , ref: "room"}]


})

const teacherModel = mongoose.model('teacher' , BCSchema)
module.exports = teacherModel