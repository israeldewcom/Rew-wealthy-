// models/KYC.js
const mongoose = require('mongoose');

const kycSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  id_type: {
    type: String,
    required: true,
    enum: ['national_id', 'passport', 'drivers_license']
  },
  id_number: {
    type: String,
    required: true
  },
  id_front_image: {
    type: String,
    required: true
  },
  id_back_image: {
    type: String,
    required: true
  },
  selfie_with_id: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  reviewed_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  reviewed_at: Date,
  rejection_reason: String
}, {
  timestamps: true
});

module.exports = mongoose.model('KYC', kycSchema);
