// barcode/barcodebackend/models/Barcode.js
const mongoose = require('mongoose');

const barcodeSchema = new mongoose.Schema({
  value: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  location: { type: String },
  pointsAwarded: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Barcode', barcodeSchema);