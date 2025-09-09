const mongoose = require('mongoose');

const complaintSchema = new mongoose.Schema({
  roomId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'room', // Changed to lowercase
    required: true 
  },
  roomNumber: {
    type: String,
    required: true
  },
  teacherId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'teacher', // Changed to lowercase
    required: true 
  },
  teacherEmail: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true,
    enum: ['Projector', 'Blackboard', 'Fan', 'AC', 'Cleanliness', 'Furniture', 'Electrical', 'Other']
  },
  description: {
    type: String,
    required: true,
    maxlength: 500
  },
  status: {
    type: String,
    enum: ['Pending', 'In Progress', 'Resolved', 'Closed'],
    default: 'Pending'
  },
  priority: {
    type: String,
    enum: ['Low', 'Medium', 'High', 'Critical'],
    default: 'Medium'
  },
  images: [{
    data: Buffer,
    contentType: String,
    originalName: String,
    uploadDate: {
      type: Date,
      default: Date.now
    }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },
  adminNotes: [{
      note: String,
      addedBy: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'admin' // Changed to lowercase
      },
      addedAt: {
          type: Date,
          default: Date.now
      }
  }]
});

// Update the updatedAt field before saving
complaintSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Complaint', complaintSchema);