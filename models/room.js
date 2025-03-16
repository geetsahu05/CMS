const mongoose = require("mongoose")


const roomSchema = new mongoose.Schema({
    floor_id: {
        type: mongoose.Schema.ObjectId, 
        ref: "floor"
    },

    room_Number: String,

    Booked_by: {
        userId: {
            type: mongoose.Schema.ObjectId,
            refPath: "Booked_by.userType",
            default: null
        },
        userEmail: {
            type: String,
            default: null
        },
        userType: {
            type: String,
            enum: ["BC", "Teacher" , "Student"],
            default: null
        }
    },

    branch: {
        type: String,
        default: null
    },
    
    batch: {
        type: String,
        default: null
    },

    assigned_teacher:{

        type: mongoose.Schema.ObjectId,
        ref: "teacher",
        default: null
    },

    booking_status: String,

    booking_time: {
        from_time: {
            type: Date,
            default: null
        },
        to_time: {
            type: Date,
            default: null
        }
    }

});

const roomModel = mongoose.model('room' , roomSchema)
module.exports = roomModel