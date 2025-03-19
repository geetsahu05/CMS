const express = require("express")
const app = express()
const jwt = require('jsonwebtoken');
const bcrypt = require("bcryptjs")
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
require("dotenv").config();

const AdminModel = require("./models/admin")
const BCModel = require("./models/BC")
const teacherModel = require("./models/teacher")
const roomModel = require("./models/room");
const floorModel = require("./models/floor")
const buildingModel = require("./models/building");


app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.use(cookieParser());


const SK = process.env.SECRET_KEY

const bc_authMiddleware = (req, res, next) => {
    const token = req.cookies.BCtoken;

    if (!token) {
        return res.status(401).json({ message: "Unauthorized: No token provided" });
    }

    try {
        const decoded = jwt.verify(token, SK);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ message: "Forbidden: Invalid token" });
    }
};

const admin_authMiddleware = (req, res, next) => {
    const token = req.cookies.Admintoken;

    if (!token) {
        return res.status(401).json({ message: "Unauthorized: No token provided" });
    }

    try {
        const decoded = jwt.verify(token, SK);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ message: "Forbidden: Invalid token" });
    }
};

const teacher_authMiddleware = (req, res, next) => {
    const token = req.cookies.Teachertoken;

    if (!token) {
        return res.status(401).json({ message: "Unauthorized: No token provided" });
    }

    try {
        const decoded = jwt.verify(token, SK);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ message: "Forbidden: Invalid token" });
    }
};

app.get("/" , (req , res) => {

    res.render("landing")
})


app.get("/register_batch_coordinator" , (req , res) => {

    res.render("BCRegis")
})

app.post("/register_batch_coordinator" , async (req , res) => {

    try {

        let { name , email , password} = req.body


        
        const existingUser = await BCModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await BCModel.create({ name, email, password: hashedPassword});
        
        res.redirect('/login_bc')

        
    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
})

app.get("/login_bc" , async ( req , res) => {

    res.render("loginBC")

})

app.post("/login_bc", async (req, res) => {
    try {
        const { email, password } = req.body;

        const BC = await BCModel.findOne({ email });
        if (!BC) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        const isMatch = await bcrypt.compare(password, BC.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid email or password" });
        }


        const token = jwt.sign(
            { id: BC._id, email: BC.email },
         SK,
        );

        res.cookie("BCtoken", token); //testing point

        res.redirect("/BC_dashboard")

    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

app.get("/register_teacher" , (req , res) => {

    res.render("teacherRegis")
})

app.post("/register_teacher" , async (req , res) => {

    try {

        let { name , email , password} = req.body


        
        const existingUser = await teacherModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await teacherModel.create({ name, email, password: hashedPassword});
        
        res.redirect('/teacher_log')

        
    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
})

app.get("/teacher_log" , async ( req , res) => {

    res.render("teacherlog")

})

app.post("/teacher_log", async (req, res) => {
    try {
        const { email, password } = req.body;

        const teacher = await teacherModel.findOne({ email });
        if (!teacher) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        const isMatch = await bcrypt.compare(password, teacher.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid email or password" });
        }


        const token = jwt.sign(
            { id: teacher._id, email: teacher.email },
         SK,
        );

        res.cookie("Teachertoken", token); //testing point

        res.redirect("/teacher_landing_dashboard")

    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

app.get("/register_admin" , (req , res) => {

    res.render("adminRegis")

})

app.post("/register_admin" , async (req , res) => {

    try {

        let { name , email , password} = req.body

        
        const existingUser = await AdminModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await AdminModel.create({ name, email, password: hashedPassword});

        // const token = jwt.sign(
        //     { id: newUser._id, email: newUser.email },
        //     SK,
        //     { expiresIn: "1h" }
        // );

        //res.cookie("token" , token)
        res.redirect('/login_admin')

        
    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
})

app.get("/login_admin", (req, res) => {
    res.render("adminlog");
});

app.post("/login_admin", async (req, res) => {
    try {
        const { email, password } = req.body;

        const admin = await AdminModel.findOne({ email });
        if (!admin) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid email or password" });
        }


        const token = jwt.sign(
            { id: admin._id, email: admin.email },
         SK,
        );

        res.cookie("Admintoken", token); //testing point

        res.redirect("/adminDash")

    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
});


app.get("/adminDash", admin_authMiddleware , async (req, res) => { //testing point
    try {
        if (!req.user) {
            return res.redirect('/login_admin');
        }

        // Find the admin in the database
        let admin = await AdminModel.findOne({ email: req.user.email });

        if (!admin) {
            return res.redirect('/login_admin'); // If admin not found, redirect to login
        }

        // Fetch all buildings
        let buildings = await buildingModel.find();

        // Render the admin dashboard with admin details and buildings
        res.render("adminDash", { 
            admin: { name: admin.name, email: admin.email },
            buildings
        });

    } catch (error) {
        console.error("Error fetching admin dashboard:", error);
        res.status(500).send("Server Error");
    }
});

app.get("/Teacher_dashboard", teacher_authMiddleware, async (req, res) => {

    try {

        let currentTeacher = await teacherModel.findOne({email:req.user.email})
        let buildings = await buildingModel.find();
        res.render('teacherDash', { buildings , currentTeacher});  // Correctly pass buildings as an object
    } catch (error) {
        console.error("Error fetching buildings:", error);
        res.status(500).send("Internal Server Error");
    }

});


app.get("/add_building" , (req , res) => {

    res.render('AddBuilding')
})


app.post("/add_building", async (req, res) => {
    try {
        let data = req.body;

        let createdBuilding = await buildingModel.create({
            building_name: data.buildingName,
            Total_floors: parseInt(data.numFloors),
        });

        let floorIds = [];

        for (let i = 0; i < data.floors.length; i++) {
            let floorData = data.floors[i];


            let createdFloor = await floorModel.create({
                building_id: createdBuilding._id,
                floor_Number: i + 1, 
            });

            floorIds.push(createdFloor._id); 

            let roomIds = [];


            for (let roomNum = parseInt(floorData.startRoom); roomNum <= parseInt(floorData.endRoom); roomNum++) {
                let createdRoom = await roomModel.create({
                    floor_id: createdFloor._id,
                    room_Number: roomNum.toString(),
                    booking_status: "Available", 
                });

                roomIds.push(createdRoom._id); 
            }

            await floorModel.findByIdAndUpdate(createdFloor._id, {
                rooms: roomIds
            });
        }

        await buildingModel.findByIdAndUpdate(createdBuilding._id, {
            floors: floorIds
        });

        res.status(201).send("Done")
    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
});


app.get("/building_overview/:buildingId", async (req, res) => {
    try {
        let building = await buildingModel.findById(req.params.buildingId)
            .populate({
                path: "floors",
                populate: { path: "rooms" }
            });

        if (!building) return res.status(404).send("Building not found");

        res.render("buildingOverview", { building });
    } catch (error) {
        console.error(error);
        res.status(500).send("Server Error");
    }
});


//testing Paased 👍🏻

app.get("/BC_dashboard", bc_authMiddleware , async (req, res) => {
    try {

        let currentBC = await BCModel.findOne({email:req.user.email})
        let buildings = await buildingModel.find();
        res.render('roomBooking', { buildings , currentBC});  // Correctly pass buildings as an object
    } catch (error) {
        console.error("Error fetching buildings:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.get('/getFloors/:buildingId', async (req, res) => {
    try {
        const building = await buildingModel.findById(req.params.buildingId).populate('floors');
        res.json({ floors: building.floors });
    } catch (error) {
        res.status(500).json({ error: "Error fetching floors" });
    }
});

app.get('/getRooms/:floorId', async (req, res) => {
    try {
        const floor = await floorModel.findById(req.params.floorId).populate('rooms');
        res.json({ rooms: floor.rooms });
    } catch (error) {
        res.status(500).json({ error: "Error fetching rooms" });
    }
});

app.post('/bookRooms', bc_authMiddleware, async (req, res) => {
    try {
        const selectedRooms = JSON.parse(req.body.selectedRooms);

        console.log(selectedRooms)

        // Fetch the current user
        const currentUser = await BCModel.findOne({ email: req.user.email });
        if (!currentUser) {
            return res.status(404).json({ error: "User not found" });
        }

        // Update all selected rooms with branch and batch details
        await Promise.all(selectedRooms.map(({ roomId, branch, batch }) =>
            roomModel.findByIdAndUpdate(roomId, {
                $set: {
                    "Booked_by.userId": currentUser._id,
                    "Booked_by.userEmail": currentUser.email,
                    "Booked_by.userType": "BC",
                    booking_status: "Booked",
                    branch: branch || "Not Specified",
                    batch: batch || "Not Specified"
                }
            })
        ));

        res.redirect("/BC_dashboard");
    } catch (error) {
        console.error("Error booking rooms:", error);
        res.status(500).json({ error: "Error booking rooms" });
    }
});


app.post('/TeacherbookRooms', teacher_authMiddleware , async (req, res) => {
    try {
        const selectedRooms = JSON.parse(req.body.selectedRooms);

        console.log(selectedRooms)

        // Fetch the current user
        const currentUser = await teacherModel.findOne({ email: req.user.email });
        if (!currentUser) {
            return res.status(404).json({ error: "User not found" });
        }

        // Update all selected rooms with branch and batch details
        await Promise.all(selectedRooms.map(({ roomId, branch, batch }) =>
            roomModel.findByIdAndUpdate(roomId, {
                $set: {
                    "Booked_by.userId": currentUser._id,
                    "Booked_by.userEmail": currentUser.email,
                    "Booked_by.userType": "Teacher",
                    booking_status: "Booked",
                    branch: branch || "Not Specified",
                    batch: batch || "Not Specified"
                }
            })
        ));

        res.redirect("Teacher_dashboard");
    } catch (error) {
        console.error("Error booking rooms:", error);
        res.status(500).json({ error: "Error booking rooms" });
    }
});


app.put("/freeRooms", async (req, res) => {
    try {
        const { roomIds } = req.body;

        if (!roomIds || roomIds.length === 0) {
            return res.status(400).json({ success: false, message: "No rooms selected" });
        }

        // Extract only the `roomId` values from the array of objects
        const roomIdList = roomIds.map(room => room.roomId);

        await Promise.all(roomIdList.map(roomId => 
            roomModel.findByIdAndUpdate(roomId, { 
                $set: {
                    "Booked_by.userId": null,
                    "Booked_by.userEmail": null,
                    "Booked_by.userType": null,
                    booking_status: "Available",
                    branch: null,
                    batch: null
                }
            })
        ));

        res.redirect("/BC_dasboard");

    } catch (error) {
        console.error("Error freeing rooms:", error);
        res.status(500).json({ success: false, message: "Server error" });
    }
});



// teacher class attend feature testing

app.get("/attendClassroom", teacher_authMiddleware , async (req, res) => {
    try {
        const buildings = await buildingModel.find();
        const teacher = await teacherModel.findOne({email: req.user.email})
        console.log(req.user) // Fetch all available buildings
        res.render("attendRoom", { buildings, teacher: teacher._id }); // Pass data to EJS
    } catch (error) {
        console.error("Error rendering classroom page:", error);
        res.status(500).send("Internal Server Error");
    }
});


app.get('/availableBuildings', async (req, res) => {
    try {
        const buildings = await buildingModel.find();
        res.json({ buildings });
    } catch (error) {
        console.error("Error fetching buildings:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


app.get('/availableFloors/:buildingId', async (req, res) => {
    try {
        const building = await buildingModel.findById(req.params.buildingId).populate('floors');
        res.json({ floors: building.floors });
    } catch (error) {
        console.error("Error fetching floors:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


app.get('/availableRooms/:floorId', async (req, res) => {
    try {
        const floor = await floorModel.findById(req.params.floorId).populate({
            path: 'rooms',
            match: { assigned_teacher: null }  // Get only available rooms
        });
        res.json({ rooms: floor.rooms });
    } catch (error) {
        console.error("Error fetching rooms:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


app.post("/bookRoom", async (req, res) => {
    try {
        const { roomId, teacherId, from_time, to_time } = req.body;

        // Validate ObjectId
        if (!mongoose.Types.ObjectId.isValid(roomId) || !mongoose.Types.ObjectId.isValid(teacherId)) {
            return res.status(400).json({ message: "Invalid room or teacher ID." });
        }

        const updatedRoom = await roomModel.findOneAndUpdate(
            { _id: roomId }, // Find the existing room by ID
            { 
                assigned_teacher: teacherId, 
                booking_time: { from_time, to_time } // Corrected structure
            },
            { new: true } // Return the updated document
        );

        if (!updatedRoom) {
            return res.status(404).json({ message: "Room not found." });
        }

        res.json({ message: "Room booked successfully", updatedRoom });
    } catch (error) {
        console.error("Error booking room:", error);
        res.status(500).json({ message: "Server error" });
    }
});

app.get("/teacher_landing_dashboard", teacher_authMiddleware, async (req, res) => {
    try {
        const teacherId = req.user.id;

        // Fetch rooms booked by the teacher and populate floor & building details
        const bookedRooms = await roomModel
            .find({ "Booked_by.userId": teacherId })
            .populate({
                path: "floor_id",
                populate: {
                    path: "building_id"
                }
            });

        // Fetch rooms the teacher is attending and populate floor & building details
        const attendingRooms = await roomModel
            .find({ assigned_teacher: teacherId })
            .populate({
                path: "floor_id",
                populate: {
                    path: "building_id"
                }
            });

        res.render("teacherDash2", { bookedRooms, attendingRooms });
    } catch (error) {
        console.error("Error fetching teacher dashboard:", error);
        res.status(500).send("Server Error");
    }
});



app.post("/freeClassroom", teacher_authMiddleware, async (req, res) => {
    try {
        const { roomId } = req.body;
        const teacherId = req.user.id;

        const room = await roomModel.findOne({ _id: roomId, assigned_teacher: teacherId });

        if (!room) {
            return res.status(404).json({ message: "Room not found or not assigned to you." });
        }

        // Free the room by resetting its details
        room.assigned_teacher = null;
        room.booking_time = null;

        await room.save();
        res.json({ message: "Classroom freed successfully!" });
    } catch (error) {
        console.error("Error freeing classroom:", error);
        res.status(500).json({ message: "Server error" });
    }
});

app.listen(process.env.PORT)