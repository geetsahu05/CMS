College Room Management System

📌 Overview

The College Room Management System is a web-based application designed to efficiently manage room bookings and class schedules for colleges. The system allows Admins, Batch Coordinators, and Teachers to manage room assignments, track availability, and optimize classroom usage.

🚀 Features

👨‍💼 Admin Panel

Building & Room Management:

Create and configure buildings, floors, and rooms.

Assign rooms to specific departments or batches.

Timetable & Scheduling:

View and manage room allocations.

Assign rooms for different branches (e.g., CSE-A, IT-B, etc.).

Booking & Monitoring:

Track booked and available rooms.

Receive notifications when a booked room is unoccupied due to teacher absence.

User Management:

Manage Teachers and Batch Coordinators.

Grant or revoke access rights.

📅 Batch Coordinator Panel

Batch-Wise Room Allocation:

Select multiple rooms and assign them to specific branches.

Automatically allocate rooms without requiring teacher details.

Schedule Monitoring:

View and update room allocations for ongoing batches.

Room Availability Insights:

Check room booking status and optimize scheduling.

🎓 Teacher Dashboard

Room Booking:

Book available rooms for lectures.

View all booked and available rooms.

Attend Class:

Check assigned classes for the day.

View room details and schedules.

Dashboard Insights:

Two sections:

Booked Rooms: Lists rooms booked by the teacher.

Attending Rooms: Shows scheduled classes, including time slots.

🏗️ Tech Stack

Frontend: HTML, EJS, Tailwind CSS, JavaScript

Backend: Node.js, Express.js

Database: MongoDB (Mongoose)

Authentication: JWT-based authentication

Other Integrations:

Google Sheets for timetable management

QR Code for dynamic access to room details

⚙️ Installation & Setup

Clone the repository:

git clone https://github.com/your-repo/college-room-management.git
cd college-room-management

Install dependencies:

npm install

Set up .env file:

PORT=3000
MONGODB_URI=mongodb://127.0.0.1:27017/yourDatabase
JWT_SECRET=your_secret_key

Start the server:

npm start

📌 Usage

Admin: Log in and manage buildings, rooms, and schedules.

Batch Coordinators: Allocate rooms for different branches.

Teachers: Book rooms and attend scheduled classes.

📝 Future Enhancements

Automated Room Suggestions: Suggest available rooms based on capacity.

Real-time Attendance Tracking: Check if the assigned teacher is present.

Enhanced Notifications: Notify users of last-minute room changes.

🎯 Made for Efficient Classroom Management 🚀
