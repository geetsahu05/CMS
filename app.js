const express = require("express")
const path = require("path");
const app = express()
const jwt = require('jsonwebtoken');
const bcrypt = require("bcryptjs")
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const passport = require('passport');
const GoogleStrategy = require("passport-google-oauth20").Strategy;
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


const session = require("express-session");

app.use(session({
  secret: process.env.SESSION_SECRET || "yoursecret",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());



app.use(passport.initialize());



const SK = process.env.SECRET_KEY

// Helper to pick model by role string
const getModelByRole = (role) => {
  switch ((role || '').toLowerCase()) {
    case 'admin': return AdminModel;
    case 'teacher': return teacherModel;
    case 'bc':
    case 'batch_coordinator':
    case 'batch-coordinator':
    default: return BCModel;
  }
};

// Add debug middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/callback",
  passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    console.log('Google profile received:', profile);
    
    // Extract role from state parameter
    const role = req.query.state || 'bc';
    console.log('Role from state:', role);
    
    const Model = getModelByRole(role);

    const googleId = profile.id;
    const email = profile.emails?.[0]?.value;
    const name = profile.displayName;
    const picture = profile.photos?.[0]?.value;

    if (!email) {
      return done(new Error("Email not provided by Google"), null);
    }

    let user = await Model.findOne({ 
      $or: [{ googleId }, { email }] 
    });

    if (!user) {
      user = await Model.create({
        name,
        email,
        googleId,
        picture,
        authProvider: "google"
      });
      console.log('New user created:', user);
    } else {
      user.googleId = googleId;
      user.picture = picture;
      user.authProvider = "google";
      await user.save();
      console.log('Existing user updated:', user);
    }

    const token = jwt.sign(
      { id: user._id, email: user.email, role: role.toLowerCase() },
      SK,
      { expiresIn: '1h' }
    );

    return done(null, { user, token, role: role.toLowerCase() });
  } catch (error) {
    console.error('Google strategy error:', error);
    return done(error, null);
  }
}));

// ✅ FIXED: SINGLE CALLBACK ROUTE (PUT THIS FIRST)
app.get('/auth/google/callback',
  (req, res, next) => {
    console.log('=== CALLBACK HIT ===');
    console.log('OAuth callback - query params:', req.query);
    console.log('OAuth callback - state:', req.query.state);
    
    passport.authenticate('google', { 
      failureRedirect: '/?error=auth_failed',
      session: false 
    }, (err, user, info) => {
      if (err) {
        console.error('Passport auth error:', err);
        return res.redirect('/?error=auth_error');
      }
      if (!user) {
        console.error('No user returned:', info);
        return res.redirect('/?error=no_user');
      }
      req.user = user;
      next();
    })(req, res, next);
  },
  (req, res) => {
    try {
      const { token, role } = req.user;
      
      if (!token) {
        console.error('No token in user object');
        return res.redirect('/?error=no_token');
      }

      let cookieName, redirectUrl;
      
      switch(role) {
        case 'admin':
          cookieName = "Admintoken";
          redirectUrl = "/adminDash";
          break;
        case 'teacher':
          cookieName = "Teachertoken";
          redirectUrl = "/teacher_landing_dashboard";
          break;
        case 'bc':
        default:
          cookieName = "BCtoken";
          redirectUrl = "/BC_dashboard";
      }

      res.cookie(cookieName, token, {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 // 1 hour
      });

      console.log('OAuth successful, redirecting to:', redirectUrl);
      res.redirect(redirectUrl);
    } catch (error) {
      console.error('Callback handler error:', error);
      res.redirect('/?error=callback_error');
    }
  }
);

// ✅ ADD THIS ROUTE FOR QUERY PARAMETER FORMAT
app.get('/auth/google', (req, res, next) => {
  const role = req.query.role || 'bc';
  console.log('Starting OAuth for role (query):', role);
  
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    state: role,
    session: false
  })(req, res, next);
});

// ✅ FIXED: SINGLE INITIATION ROUTE (PUT THIS AFTER CALLBACK)
app.get('/auth/google/:role', (req, res, next) => {
  const role = req.params.role;
  console.log('Starting OAuth for role:', role);
  
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    state: role,
    session: false
  })(req, res, next);
});

// Test route
app.get('/test-oauth', (req, res) => {
  res.json({
    clientId: process.env.GOOGLE_CLIENT_ID ? 'Set' : 'Missing',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET ? 'Set' : 'Missing',
    callbackUrl: 'http://localhost:3000/auth/google/callback'
  });
});

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

        res.cookie("Teachertoken", token); 

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

app.get("/QRgenerateroom/:roomID", teacher_authMiddleware, async (req, res) => {
    try {
        const roomID = req.params.roomID;

        res.render("qrBooking", { roomID });
    } catch (error) {
        console.error("Error loading booking interface:", error);
        res.status(500).json({ message: "Server error" });
    }
});

app.post("/bookRoomFromQR", teacher_authMiddleware, async (req, res) => {
    try {
        const { roomID, from_time, to_time } = req.body;
        const teacherId = req.user.id; // Extracted from token via middleware

        // Validate ObjectId
        if (!mongoose.Types.ObjectId.isValid(roomID) || !mongoose.Types.ObjectId.isValid(teacherId)) {
            return res.status(400).json({ message: "Invalid room or teacher ID." });
        }

        const updatedRoom = await roomModel.findOneAndUpdate(
            { _id: roomID },
            {
                assigned_teacher: teacherId,
                booking_time: {
                    from_time: new Date(from_time),
                    to_time: new Date(to_time),
                },
            },
            { new: true }
        );

        if (!updatedRoom) {
            return res.status(404).json({ message: "Room not found." });
        }

        res.json({ message: "✅ Room booked successfully via QR!", updatedRoom });
    } catch (error) {
        console.error("Error booking room via QR:", error);
        res.status(500).json({ message: "Booking failed due to server error." });
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

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));