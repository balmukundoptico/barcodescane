const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  mobile: { 
    type: String, 
    required: true, 
    unique: true,
    validate: {
      validator: function(v) {
        return /^\d{10}$/.test(v);
      },
      message: props => `${props.value} is not a valid 10-digit mobile number!`
    }
  },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  location: { type: String },
  status: { type: String, enum: ['pending', 'approved', 'disapproved'], default: 'pending' },
  points: { type: Number, default: 0 },
  notificationToken: { type: String },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);