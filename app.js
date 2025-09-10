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

//Testing
const Complaint = require('./models/complaint');
const multer = require('multer');
const nodemailer = require('nodemailer');





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
// Serve static files from uploads directory
app.use('/uploads', express.static('uploads'));


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

// Email error handling
process.on('unhandledRejection', (err) => {
  console.log('Unhandled Rejection:', err);
  // Don't crash the app on email errors
});

process.on('uncaughtException', (err) => {
  console.log('Uncaught Exception:', err);
  // Don't crash the app on email errors
});

// Create transporter
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});


// Function to send booking confirmation email
async function sendBookingConfirmation(email, bookingDetails, userType) {
  try {
    const { roomNumber, from_time, to_time, branch, batch, buildingName, floorNumber } = bookingDetails;
    
    // Format dates
    const startTime = new Date(from_time);
    const endTime = new Date(to_time);
    
    // Create Google Calendar link
    const calendarLink = createGoogleCalendarLink(bookingDetails);
    
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: `Room Booking Confirmation - Room ${roomNumber}`,
      html: generateEmailTemplate(bookingDetails, userType, calendarLink)
    };
    
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent:', info.messageId);
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    return false;
  }
}

// Function to create Google Calendar link
function createGoogleCalendarLink(bookingDetails) {
  const { roomNumber, from_time, to_time, branch, batch, buildingName } = bookingDetails;
  
  const startTime = new Date(from_time);
  const endTime = new Date(to_time);
  
  // Format dates for Google Calendar (YYYYMMDDTHHmmssZ)
  const formatDate = (date) => {
    return date.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
  };
  
  const start = formatDate(startTime);
  const end = formatDate(endTime);
  
  const details = `Room Booking: Room ${roomNumber}, ${buildingName}`;
  const description = `Room: ${roomNumber}\\nBuilding: ${buildingName}\\nBranch: ${branch}\\nBatch: ${batch}`;
  
  return `https://calendar.google.com/calendar/render?action=TEMPLATE&text=${encodeURIComponent(details)}&dates=${start}/${end}&details=${encodeURIComponent(description)}&location=${encodeURIComponent(buildingName)}`;
}

// Function to generate email HTML template
function generateEmailTemplate(bookingDetails, userType, calendarLink) {
  const { roomNumber, from_time, to_time, branch, batch, buildingName, floorNumber } = bookingDetails;
  
  const startTime = new Date(from_time).toLocaleString();
  const endTime = new Date(to_time).toLocaleString();
  
  return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9fafb; padding: 20px; border-radius: 0 0 10px 10px; }
        .details { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .button { display: inline-block; background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 10px 0; }
        .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Room Booking Confirmation</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>Your room booking has been confirmed. Here are your booking details:</p>
            
            <div class="details">
                <h2>Booking Information</h2>
                <p><strong>Room:</strong> ${roomNumber}</p>
                <p><strong>Building:</strong> ${buildingName}</p>
                ${floorNumber ? `<p><strong>Floor:</strong> ${floorNumber}</p>` : ''}
                <p><strong>Date & Time:</strong> ${startTime} to ${endTime}</p>
                ${branch ? `<p><strong>Branch:</strong> ${branch}</p>` : ''}
                ${batch ? `<p><strong>Batch:</strong> ${batch}</p>` : ''}
                <p><strong>Booked by:</strong> ${userType}</p>
            </div>
            
            <p>Add this event to your calendar:</p>
            <a href="${calendarLink}" class="button" target="_blank">
                Add to Google Calendar
            </a>
            
            <p>If you have any questions, please contact the administration.</p>
        </div>
        <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
  `;
}

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

const callbackURL = process.env.NODE_ENV === 'production' 
  ? 'https://cms-4ud8.vercel.app/auth/google/callback'
  : 'http://localhost:3000/auth/google/callback';

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: callbackURL,
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


// app.get("/adminDash", admin_authMiddleware , async (req, res) => { //testing point
//     try {
//         if (!req.user) {
//             return res.redirect('/login_admin');
//         }

//         // Find the admin in the database
//         let admin = await AdminModel.findOne({ email: req.user.email });

//         if (!admin) {
//             return res.redirect('/login_admin'); // If admin not found, redirect to login
//         }

//         // Fetch all buildings
//         let buildings = await buildingModel.find();

//         // Render the admin dashboard with admin details and buildings
//         res.render("adminDash", { 
//             admin: { name: admin.name, email: admin.email },
//             buildings
//         });

//     } catch (error) {
//         console.error("Error fetching admin dashboard:", error);
//         res.status(500).send("Server Error");
//     }
// });

app.get("/adminDash", admin_authMiddleware, async (req, res) => {
    try {
        if (!req.user) {
            return res.redirect('/login_admin');
        }

        // Find the admin in the database
        let admin = await AdminModel.findOne({ email: req.user.email });

        if (!admin) {
            return res.redirect('/login_admin');
        }

        // Fetch all buildings with populated floors and rooms
        let buildings = await buildingModel.find()
            .populate({
                path: "floors",
                populate: {
                    path: "rooms"
                }
            });

        // Calculate occupancy for each building
        const buildingsWithOccupancy = buildings.map(building => {
            let totalRooms = 0;
            let occupiedRooms = 0;

            // Calculate occupancy for this building
            building.floors.forEach(floor => {
                totalRooms += floor.rooms.length;
                occupiedRooms += floor.rooms.filter(room => 
                    room.booking_status === "Booked" || room.assigned_teacher
                ).length;
            });

            const occupancyRate = totalRooms > 0 ? Math.round((occupiedRooms / totalRooms) * 100) : 0;

            return {
                ...building.toObject(),
                totalRooms,
                occupiedRooms,
                occupancyRate
            };
        });

        // Render the admin dashboard with calculated data
        res.render("adminDash", { 
            admin: { name: admin.name, email: admin.email },
            buildings: buildingsWithOccupancy
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

// app.post('/bookRooms', bc_authMiddleware, async (req, res) => {
//     try {
//         const selectedRooms = JSON.parse(req.body.selectedRooms);

//         console.log(selectedRooms)

//         // Fetch the current user
//         const currentUser = await BCModel.findOne({ email: req.user.email });
//         if (!currentUser) {
//             return res.status(404).json({ error: "User not found" });
//         }

//         // Update all selected rooms with branch and batch details
//         await Promise.all(selectedRooms.map(({ roomId, branch, batch }) =>
//             roomModel.findByIdAndUpdate(roomId, {
//                 $set: {
//                     "Booked_by.userId": currentUser._id,
//                     "Booked_by.userEmail": currentUser.email,
//                     "Booked_by.userType": "BC",
//                     booking_status: "Booked",
//                     branch: branch || "Not Specified",
//                     batch: batch || "Not Specified"
//                 }
//             })
//         ));

//         res.redirect("/BC_dashboard");
//     } catch (error) {
//         console.error("Error booking rooms:", error);
//         res.status(500).json({ error: "Error booking rooms" });
//     }
// });

// For Batch Coordinator booking
app.post('/bookRooms', bc_authMiddleware, async (req, res) => {
  try {
    const selectedRooms = JSON.parse(req.body.selectedRooms);
    const currentUser = await BCModel.findOne({ email: req.user.email });
    
    // Your existing booking logic
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

    // Send email notifications
    for (const { roomId, branch, batch } of selectedRooms) {
      const room = await roomModel.findById(roomId).populate('floor_id');
      const building = await buildingModel.findById(room.floor_id.building_id);
      
      const bookingDetails = {
        roomNumber: room.room_Number,
        from_time: new Date(), // You might want to adjust this based on your booking time
        to_time: new Date(Date.now() + 2 * 60 * 60 * 1000), // 2 hours later, adjust as needed
        branch,
        batch,
        buildingName: building.building_name,
        floorNumber: room.floor_id.floor_Number
      };
      
      await sendBookingConfirmation(currentUser.email, bookingDetails, 'Batch Coordinator');
    }

    res.redirect("/BC_dashboard");
  } catch (error) {
    console.error("Error booking rooms:", error);
    res.status(500).json({ error: "Error booking rooms" });
  }
});

// app.post('/TeacherbookRooms', teacher_authMiddleware , async (req, res) => {
//     try {
//         const selectedRooms = JSON.parse(req.body.selectedRooms);

//         console.log(selectedRooms)

//         // Fetch the current user
//         const currentUser = await teacherModel.findOne({ email: req.user.email });
//         if (!currentUser) {
//             return res.status(404).json({ error: "User not found" });
//         }

//         // Update all selected rooms with branch and batch details
//         await Promise.all(selectedRooms.map(({ roomId, branch, batch }) =>
//             roomModel.findByIdAndUpdate(roomId, {
//                 $set: {
//                     "Booked_by.userId": currentUser._id,
//                     "Booked_by.userEmail": currentUser.email,
//                     "Booked_by.userType": "Teacher",
//                     booking_status: "Booked",
//                     branch: branch || "Not Specified",
//                     batch: batch || "Not Specified"
//                 }
//             })
//         ));

//         res.redirect("Teacher_dashboard");
//     } catch (error) {
//         console.error("Error booking rooms:", error);
//         res.status(500).json({ error: "Error booking rooms" });
//     }
// });

// For Teacher booking
app.post('/TeacherbookRooms', teacher_authMiddleware, async (req, res) => {
  try {
    const selectedRooms = JSON.parse(req.body.selectedRooms);
    const currentUser = await teacherModel.findOne({ email: req.user.email });
    
    // Your existing booking logic
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

    // Send email notifications
    for (const { roomId, branch, batch } of selectedRooms) {
      const room = await roomModel.findById(roomId).populate('floor_id');
      const building = await buildingModel.findById(room.floor_id.building_id);
      
      const bookingDetails = {
        roomNumber: room.room_Number,
        from_time: new Date(), // Adjust based on your booking time
        to_time: new Date(Date.now() + 2 * 60 * 60 * 1000), // 2 hours later
        branch,
        batch,
        buildingName: building.building_name,
        floorNumber: room.floor_id.floor_Number
      };
      
      await sendBookingConfirmation(currentUser.email, bookingDetails, 'Teacher');
    }

    res.redirect("/Teacher_dashboard");
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

        // Return JSON response instead of redirect for AJAX calls
        res.json({ success: true, message: "Rooms freed successfully" });

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



// app.post("/bookRoomFromQR", teacher_authMiddleware, async (req, res) => {
//     try {
//         const { roomID, from_time, to_time } = req.body;
//         const teacherId = req.user.id; // Extracted from token via middleware

//         // Validate ObjectId
//         if (!mongoose.Types.ObjectId.isValid(roomID) || !mongoose.Types.ObjectId.isValid(teacherId)) {
//             return res.status(400).json({ message: "Invalid room or teacher ID." });
//         }

//         const updatedRoom = await roomModel.findOneAndUpdate(
//             { _id: roomID },
//             {
//                 assigned_teacher: teacherId,
//                 booking_time: {
//                     from_time: new Date(from_time),
//                     to_time: new Date(to_time),
//                 },
//             },
//             { new: true }
//         );

//         if (!updatedRoom) {
//             return res.status(404).json({ message: "Room not found." });
//         }

//         res.json({ message: "✅ Room booked successfully via QR!", updatedRoom });
//     } catch (error) {
//         console.error("Error booking room via QR:", error);
//         res.status(500).json({ message: "Booking failed due to server error." });
//     }
// });

// app.get("/teacher_landing_dashboard", teacher_authMiddleware, async (req, res) => {
//     try {
//         const teacherId = req.user.id;

//         // Fetch rooms booked by the teacher and populate floor & building details
//         const bookedRooms = await roomModel
//             .find({ "Booked_by.userId": teacherId })
//             .populate({
//                 path: "floor_id",
//                 populate: {
//                     path: "building_id"
//                 }
//             });

//         // Fetch rooms the teacher is attending and populate floor & building details
//         const attendingRooms = await roomModel
//             .find({ assigned_teacher: teacherId })
//             .populate({
//                 path: "floor_id",
//                 populate: {
//                     path: "building_id"
//                 }
//             });

//         res.render("teacherDash2", { bookedRooms, attendingRooms });
//     } catch (error) {
//         console.error("Error fetching teacher dashboard:", error);
//         res.status(500).send("Server Error");
//     }
// });

app.post("/bookRoomFromQR", teacher_authMiddleware, async (req, res) => {
  try {
    const { roomID, from_time, to_time } = req.body;
    const teacherId = req.user.id;

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
    ).populate('floor_id');

    // Send email notification
    const teacher = await teacherModel.findById(teacherId);
    const building = await buildingModel.findById(updatedRoom.floor_id.building_id);
    
    const bookingDetails = {
      roomNumber: updatedRoom.room_Number,
      from_time: new Date(from_time),
      to_time: new Date(to_time),
      buildingName: building.building_name,
      floorNumber: updatedRoom.floor_id.floor_Number
    };
    
    await sendBookingConfirmation(teacher.email, bookingDetails, 'Teacher');

    res.json({ message: "✅ Room booked successfully via QR!", updatedRoom });
  } catch (error) {
    console.error("Error booking room via QR:", error);
    res.status(500).json({ message: "Booking failed due to server error." });
  }
});


app.get("/teacher_landing_dashboard", teacher_authMiddleware, async (req, res) => {
    try {
        const teacherId = req.user.id;

        // Fetch the current teacher details
        const currentTeacher = await teacherModel.findById(teacherId);
        if (!currentTeacher) {
            return res.status(404).send("Teacher not found");
        }

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

        res.render("teacherDash2", { 
            bookedRooms, 
            attendingRooms,
            currentTeacher // Make sure this is passed to the template
        });
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


//Testing........
// Configure multer for memory storage
const storage = multer.memoryStorage();

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 2 * 1024 * 1024 // 2MB limit
  },
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});


// Submit a complaint with buffer storage
app.post('/complaint', teacher_authMiddleware, upload.array('images', 3), async (req, res) => {
  try {
    const { roomId, roomNumber, category, description, priority } = req.body;
    
    // Validate required fields
    if (!roomId || !roomNumber || !category || !description) {
      return res.status(400).render('complaintForm', {
        roomId: roomId,
        roomNumber: roomNumber,
        error: "All required fields must be filled out."
      });
    }
    
    // Prepare image data
    const imageData = [];
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        imageData.push({
          data: file.buffer,
          contentType: file.mimetype,
          originalName: file.originalname
        });
      }
    }
    
    // Create new complaint
    const complaint = new Complaint({
      roomId,
      roomNumber,
      teacherId: req.user.id,
      teacherEmail: req.user.email,
      category,
      description,
      priority: priority || 'Medium',
      images: imageData
    });
    
    await complaint.save();
    res.redirect('/complaint-success');
    
  } catch (error) {
    console.error("Complaint submission error:", error);
    
    // Check if it's a validation error
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      return res.status(400).render('complaintForm', {
        roomId: req.body.roomId,
        roomNumber: req.body.roomNumber,
        error: errors.join(', ')
      });
    }
    
    res.status(500).render('complaintForm', {
      roomId: req.body.roomId,
      roomNumber: req.body.roomNumber,
      error: "Server error. Please try again later."
    });
  }
});

// Serve complaint images from Buffer
app.get('/complaint-image/:complaintId/:imageIndex', async (req, res) => {
  try {
    const complaint = await Complaint.findById(req.params.complaintId);
    if (!complaint || !complaint.images[req.params.imageIndex]) {
      return res.status(404).send('Image not found');
    }
    
    const image = complaint.images[req.params.imageIndex];
    res.set('Content-Type', image.contentType);
    res.send(image.data);
  } catch (error) {
    console.error("Error serving image:", error);
    res.status(500).send('Error retrieving image');
  }
});

// Get all complaints for a teacher
app.get('/my-complaints', teacher_authMiddleware, async (req, res) => {
  try {
    const complaints = await Complaint.find({ teacherId: req.user.id })
      .sort({ createdAt: -1 });
    
    res.render('myComplaints', { complaints });
  } catch (error) {
    console.error("Error fetching complaints:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Get complaint page with room info
app.get('/complaint/:roomId', teacher_authMiddleware, async (req, res) => {
  try {
    const room = await roomModel.findById(req.params.roomId);
    if (!room) {
      return res.status(404).json({ message: "Room not found" });
    }
    
    res.render('complaintForm', { 
      roomId: req.params.roomId, 
      roomNumber: room.room_Number,
      teacherId: req.user.id,
      teacherEmail: req.user.email,
      error: req.query.error || null
    });
  } catch (error) {
    console.error("Error loading complaint form:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Success page after complaint submission
app.get('/complaint-success', (req, res) => {
  res.render('complaintSuccess');
});



// Admin Complaint Routes

// Get all complaints (admin view) - UPDATED VERSION
app.get('/admin/complaints', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const status = req.query.status || 'all';
        const priority = req.query.priority || 'all';
        const category = req.query.category || 'all';
        
        // Build filter object
        let filter = {};
        if (status !== 'all') filter.status = status;
        if (priority !== 'all') filter.priority = priority;
        if (category !== 'all') filter.category = category;
        
        // Use populate with correct model names (now lowercase)
        let complaints = await Complaint.find(filter)
            .populate('roomId', 'room_Number') // Now references 'room' correctly
            .populate('teacherId', 'name email')
            .sort({ createdAt: -1 })
            .limit(limit)
            .skip((page - 1) * limit);
            
        const totalComplaints = await Complaint.countDocuments(filter);
        const totalPages = Math.ceil(totalComplaints / limit);
        
        // Get statistics for dashboard
        const complaintStats = await Complaint.aggregate([
            {
                $group: {
                    _id: '$status',
                    count: { $sum: 1 }
                }
            }
        ]);
        
        const priorityStats = await Complaint.aggregate([
            {
                $group: {
                    _id: '$priority',
                    count: { $sum: 1 }
                }
            }
        ]);
        
        res.render('adminComplaints', {
            complaints,
            currentPage: page,
            totalPages,
            totalComplaints,
            filters: { status, priority, category },
            stats: {
                byStatus: complaintStats,
                byPriority: priorityStats
            }
        });
    } catch (error) {
        console.error("Error fetching complaints:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

// Get single complaint details - UPDATED VERSION
app.get('/admin/complaints/:id', admin_authMiddleware, async (req, res) => {
    try {
        const complaint = await Complaint.findById(req.params.id)
            .populate('roomId', 'room_Number') // Now references 'room' correctly
            .populate('teacherId', 'name email phone');
            
        if (!complaint) {
            return res.status(404).json({ message: "Complaint not found" });
        }
        
        res.json(complaint);
    } catch (error) {
        console.error("Error fetching complaint:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

// Update complaint status
app.put('/admin/complaints/:id/status', admin_authMiddleware, async (req, res) => {
    try {
        const { status, adminNotes } = req.body;
        
        const complaint = await Complaint.findByIdAndUpdate(
            req.params.id,
            { 
                status,
                adminNotes: adminNotes || undefined,
                updatedAt: new Date()
            },
            { new: true }
        );
        
        if (!complaint) {
            return res.status(404).json({ message: "Complaint not found" });
        }
        
        res.json({ message: "Status updated successfully", complaint });
    } catch (error) {
        console.error("Error updating complaint:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

// Add note to complaint
app.post('/admin/complaints/:id/notes', admin_authMiddleware, async (req, res) => {
    try {
        const { note } = req.body;
        
        const complaint = await Complaint.findByIdAndUpdate(
            req.params.id,
            { 
                $push: { 
                    adminNotes: {
                        note,
                        addedBy: req.user.id,
                        addedAt: new Date()
                    }
                },
                updatedAt: new Date()
            },
            { new: true }
        );
        
        if (!complaint) {
            return res.status(404).json({ message: "Complaint not found" });
        }
        
        res.json({ message: "Note added successfully", complaint });
    } catch (error) {
        console.error("Error adding note:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

// Delete complaint
app.delete('/admin/complaints/:id', admin_authMiddleware, async (req, res) => {
    try {
        const complaint = await Complaint.findByIdAndDelete(req.params.id);
        
        if (!complaint) {
            return res.status(404).json({ message: "Complaint not found" });
        }
        
        res.json({ message: "Complaint deleted successfully" });
    } catch (error) {
        console.error("Error deleting complaint:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

// Get complaint statistics
app.get('/admin/complaints-stats', admin_authMiddleware, async (req, res) => {
    try {
        const stats = await Complaint.aggregate([
            {
                $facet: {
                    statusCounts: [
                        { $group: { _id: '$status', count: { $sum: 1 } } }
                    ],
                    priorityCounts: [
                        { $group: { _id: '$priority', count: { $sum: 1 } } }
                    ],
                    categoryCounts: [
                        { $group: { _id: '$category', count: { $sum: 1 } } }
                    ],
                    monthlyCounts: [
                        {
                            $group: {
                                _id: {
                                    year: { $year: '$createdAt' },
                                    month: { $month: '$createdAt' }
                                },
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { '_id.year': -1, '_id.month': -1 } },
                        { $limit: 6 }
                    ]
                }
            }
        ]);
        
        res.json(stats[0]);
    } catch (error) {
        console.error("Error fetching stats:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));