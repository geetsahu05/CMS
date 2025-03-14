const mongoose = require("mongoose")


const floorSchema = new mongoose.Schema({

    building_id: {
        type: mongoose.Schema.ObjectId , 
        ref: "building"
    },
    floor_Number: String,
    rooms:[{type: mongoose.Schema.ObjectId , ref: "room"}]


})

const floorModel = mongoose.model('floor' , floorSchema)
module.exports = floorModel