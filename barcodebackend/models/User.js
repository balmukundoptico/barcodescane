// barcode/barcodebackend/models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  mobile: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  location: { type: String },
  status: { type: String, enum: ['pending', 'approved', 'disapproved'], default: 'pending' },
  points: { type: Number, default: 0 },
  notificationToken: { type: String },
});

module.exports = mongoose.model('User', userSchema);