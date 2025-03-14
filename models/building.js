const mongoose = require("mongoose")


const buildingSchema = new mongoose.Schema({

    building_name: String,
    Total_floors: Number,
    floors:[{type: mongoose.Schema.ObjectId , ref: "floor"}]


})

const buildingModel = mongoose.model('building' , buildingSchema)
module.exports = buildingModel