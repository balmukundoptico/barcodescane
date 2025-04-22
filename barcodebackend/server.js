// File: backend/server.js

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const { Parser } = require('json2csv');

// Initialize Express app
const app = express();
const PORT = 5000;
const JWT_SECRET = 'your_jwt_secret_key'; // Replace with a secure key in production

// Middleware to parse JSON and handle CORS
app.use(express.json());
app.use(
  cors({
    origin: ['http://localhost:8081', 'http://localhost:19006', 'http://localhost:3000'],
    credentials: true,
  })
);

// MongoDB Atlas connection
// Replace <username>, <password>, and cluster0.mongodb.net with your MongoDB Atlas credentials
// MongoDB Atlas connection
// mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/barcodeapp', {
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://balmukundoptico:lets12help@job-connector.exb7v.mongodb.net/barcodeapp', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})

// Localhost MongoDB connection (commented out)
// mongoose.connect('mongodb://localhost:27017/barcodeapp', {
//   useNewUrlParser: true,
//   useUnifiedTopology: true,
// });

// MongoDB schemas
const UserSchema = new mongoose.Schema({
  name: String,
  mobile: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  status: { type: String, enum: ['pending', 'approved', 'disapproved'], default: 'pending' },
  points: { type: Number, default: 0 },
  location: String,
});
const BarcodeSchema = new mongoose.Schema({
  value: { type: String, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  pointsAwarded: Number,
  createdAt: { type: Date, default: Date.now },
  location: String,
});
const SettingSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  value: mongoose.Schema.Types.Mixed,
});

// MongoDB models
const User = mongoose.model('User', UserSchema);
const Barcode = mongoose.model('Barcode', BarcodeSchema);
const Setting = mongoose.model('Setting', SettingSchema);

// Middleware to verify JWT token
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(authHeader, JWT_SECRET);
    req.user = await User.findById(decoded.userId);
    if (!req.user) return res.status(401).json({ message: 'User not found' });
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Middleware to restrict access to admin users
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Input validation for registration
const validateRegister = [
  body('name').notEmpty().withMessage('Name is required'),
  body('mobile').isMobilePhone().withMessage('Valid mobile number is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
];

// Input validation for login
const validateLogin = [
  body('mobile').isMobilePhone().withMessage('Valid mobile number is required'),
  body('password').notEmpty().withMessage('Password is required'),
];

// Handle validation errors
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Register a new user
app.post('/register', validateRegister, handleValidationErrors, async (req, res) => {
  try {
    const { name, mobile, password, location } = req.body;
    const existingUser = await User.findOne({ mobile });
    if (existingUser) {
      return res.status(400).json({ message: 'Mobile number already registered' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      mobile,
      password: hashedPassword,
      location,
      status: 'pending',
    });
    await user.save();
    res.status(201).json({ message: 'User registered successfully, pending approval' });
  } catch (error) {
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Log in a user
app.post('/login', validateLogin, handleValidationErrors, async (req, res) => {
  try {
    const { mobile, password } = req.body;
    const user = await User.findOne({ mobile });
    if (!user) {
      return res.status(400).json({ message: 'Invalid mobile number or password' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid mobile number or password' });
    }
    // Check if user is approved
    if (user.status !== 'approved') {
      return res.status(403).json({
        message: user.status === 'pending' ? 'Account pending admin approval' : 'Account disapproved',
      });
    }
    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, {
      expiresIn: '1h',
    });
    res.json({
      token,
      user: {
        id: user._id.toString(), // Include user ID
        name: user.name,
        mobile: user.mobile,
        role: user.role,
      },
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Get all users (admin only)
app.get('/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Server error fetching users' });
  }
});

// Get a single user by ID (authenticated users)
app.get('/users/:id', authenticateToken, async (req, res) => {
  try {
    // Ensure the user can only access their own data or is an admin
    if (req.user._id.toString() !== req.params.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied' });
    }
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error fetching user' });
  }
});

// Update user status (admin only)
app.put('/users/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['approved', 'disapproved'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    user.status = status;
    await user.save();
    res.json({ message: `User ${status} successfully` });
  } catch (error) {
    res.status(500).json({ message: 'Server error updating user status' });
  }
});

// Update user details (admin only)
app.put('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, mobile, location, points } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    if (mobile && mobile !== user.mobile) {
      const existingUser = await User.findOne({ mobile });
      if (existingUser) {
        return res.status(400).json({ message: 'Mobile number already registered' });
      }
    }
    user.name = name || user.name;
    user.mobile = mobile || user.mobile;
    user.location = location || user.location;
    user.points = points !== undefined ? points : user.points;
    await user.save();
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error updating user' });
  }
});

// Delete a user and their barcodes (admin only)
app.delete('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    await Barcode.deleteMany({ userId: req.params.id });
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: `User and associated barcodes deleted: ${user.mobile}` });
  } catch (error) {
    res.status(500).json({ message: 'Server error deleting user' });
  }
});

// Reset user points (admin only)
app.put('/users/:id/reset-points', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    user.points = 0;
    await user.save();
    res.json({ message: `Points reset for user: ${user.mobile}` });
  } catch (error) {
    res.status(500).json({ message: 'Server error resetting points' });
  }
});

// Create a new barcode
app.post('/barcodes', authenticateToken, async (req, res) => {
  try {
    const { value, location } = req.body;
    const settings = await Setting.findOne({ key: 'pointsPerScan' });
    const points = settings ? settings.value : 50;
    const existingBarcode = await Barcode.findOne({ value });
    if (existingBarcode) {
      return res.status(400).json({ message: 'Barcode already scanned' });
    }
    const rangeSettings = await Setting.findOne({ key: 'barcodeRange' });
    if (rangeSettings) {
      const { start, end } = rangeSettings.value;
      if (value < start || value > end) {
        return res.status(400).json({ message: `Barcode value must be between ${start} and ${end}` });
      }
    }
    const barcode = new Barcode({
      value,
      userId: req.user._id,
      pointsAwarded: points,
      location,
    });
    await barcode.save();
    req.user.points += points;
    await req.user.save();
    res.status(201).json({ message: 'Barcode scanned successfully', pointsAwarded: points });
  } catch (error) {
    res.status(500).json({ message: 'Server error scanning barcode' });
  }
});

// Get all barcodes (admin only)
app.get('/barcodes', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const barcodes = await Barcode.find().populate('userId', 'name mobile');
    res.json(barcodes);
  } catch (error) {
    res.status(500).json({ message: 'Server error fetching barcodes' });
  }
});

// Get barcodes for a specific user (authenticated users)
app.get('/barcodes/user/:userId', authenticateToken, async (req, res) => {
  try {
    // Ensure the user can only access their own barcodes or is an admin
    if (req.user._id.toString() !== req.params.userId && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied' });
    }
    const barcodes = await Barcode.find({ userId: req.params.userId });
    if (!barcodes.length) {
      return res.status(404).json({ message: 'No barcodes found for this user' });
    }
    res.json(barcodes);
  } catch (error) {
    res.status(500).json({ message: 'Server error fetching user barcodes' });
  }
});

// Delete a barcode (admin only)
app.delete('/barcodes/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const barcode = await Barcode.findById(req.params.id);
    if (!barcode) {
      return res.status(404).json({ message: 'Barcode not found' });
    }
    const user = await User.findById(barcode.userId);
    if (user) {
      user.points = Math.max(0, user.points - barcode.pointsAwarded);
      await user.save();
    }
    await Barcode.findByIdAndDelete(req.params.id);
    res.json({ message: 'Barcode deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error deleting barcode' });
  }
});

// Delete all barcodes (admin only)
app.delete('/barcodes', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const barcodes = await Barcode.find();
    for (const barcode of barcodes) {
      const user = await User.findById(barcode.userId);
      if (user) {
        user.points = Math.max(0, user.points - barcode.pointsAwarded);
        await user.save();
      }
    }
    await Barcode.deleteMany({});
    res.json({ message: 'All barcodes deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error deleting all barcodes' });
  }
});

// Delete all barcodes for a specific user (admin only)
app.delete('/barcodes/user/:userId', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const barcodes = await Barcode.find({ userId: req.params.userId });
    if (!barcodes.length) {
      return res.status(404).json({ message: 'No barcodes found for this user' });
    }
    const user = await User.findById(req.params.userId);
    if (user) {
      const totalPoints = barcodes.reduce((sum, barcode) => sum + barcode.pointsAwarded, 0);
      user.points = Math.max(0, user.points - totalPoints);
      await user.save();
    }
    await Barcode.deleteMany({ userId: req.params.userId });
    res.json({ message: `All barcodes for user deleted: ${req.params.userId}` });
  } catch (error) {
    res.status(500).json({ message: 'Server error deleting user barcodes' });
  }
});

// Export barcodes as CSV (admin only)
app.get('/export-barcodes', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const barcodes = await Barcode.find().populate('userId', 'name mobile');
    const fields = [
      { label: 'Barcode Value', value: 'value' },
      { label: 'User Name', value: 'userId.name' },
      { label: 'User Mobile', value: 'userId.mobile' },
      { label: 'Points Awarded', value: 'pointsAwarded' },
      { label: 'Scan Date', value: 'createdAt' },
      { label: 'User Location', value: 'location' },
    ];
    const json2csv = new Parser({ fields });
    const csv = json2csv.parse(barcodes);
    res.header('Content-Type', 'text/csv');
    res.attachment('barcodes_export.csv');
    res.send(csv);
  } catch (error) {
    res.status(500).json({ message: 'Server error exporting barcodes' });
  }
});

// Get points per scan setting (authenticated users)
app.get('/settings/points-per-scan', authenticateToken, async (req, res) => {
  try {
    const setting = await Setting.findOne({ key: 'pointsPerScan' });
    res.json({ points: setting ? setting.value : 50 });
  } catch (error) {
    res.status(500).json({ message: 'Server error fetching points setting' });
  }
});

// Update points per scan setting (admin only)
app.put('/settings/points-per-scan', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { points } = req.body;
    if (typeof points !== 'number' || points < 0) {
      return res.status(400).json({ message: 'Invalid points value' });
    }
    await Setting.findOneAndUpdate(
      { key: 'pointsPerScan' },
      { key: 'pointsPerScan', value: points },
      { upsert: true }
    );
    res.json({ message: 'Points per scan updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error updating points setting' });
  }
});

// Get barcode range setting (authenticated users)
app.get('/settings/barcode-range', authenticateToken, async (req, res) => {
  try {
    const setting = await Setting.findOne({ key: 'barcodeRange' });
    res.json(setting ? setting.value : { start: '0', end: '9999999999999' });
  } catch (error) {
    res.status(500).json({ message: 'Server error fetching barcode range' });
  }
});

// Update barcode range setting (admin only)
app.put('/settings/barcode-range', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { start, end } = req.body;
    if (!start || !end || start > end) {
      return res.status(400).json({ message: 'Invalid barcode range' });
    }
    await Setting.findOneAndUpdate(
      { key: 'barcodeRange' },
      { key: 'barcodeRange', value: { start, end } },
      { upsert: true }
    );
    res.json({ message: 'Barcode range updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error updating barcode range' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});