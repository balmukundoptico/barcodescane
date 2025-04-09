// barcode/barcodebackend/server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { createObjectCsvWriter } = require('csv-writer');
require('dotenv').config(); // Added for environment variables
const User = require('./models/User');
const Barcode = require('./models/Barcode');

const app = express();

// Corrected CORS configuration
app.use(cors({
  origin: [
    'http://localhost:8081', // Expo web client
    'http://localhost:19006', // Expo dev server
    'https://yourfrontendurl.com', // Replace with your production frontend URL
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Include OPTIONS for preflight
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true, // Allow credentials if needed
}));

// Explicitly handle preflight OPTIONS requests for all routes
app.options('*', cors({
  origin: [
    'http://localhost:8081',
    'http://localhost:19006',
    'https://yourfrontendurl.com',
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

app.use(express.json());

// MongoDB Atlas connection using environment variable
mongoose.connect(
  process.env.MONGODB_URI || "mongodb+srv://balmukundoptico:lets@12help@job-connector.exb7v.mongodb.net/barcodescane?retryWrites=true&w=majority&appName=job-connector",
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }
).then(() => console.log('MongoDB Atlas connected'))
 .catch(err => console.error('MongoDB connection error:', err));

const JWT_SECRET = 'your-secret-key';
let pointsPerScan = 50; // Default points per scan, adjustable by admin

const authMiddleware = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
  next();
};

const sendPushNotification = async (token, title, body) => {
  const message = {
    to: token,
    sound: 'default',
    title,
    body,
    data: { someData: 'goes here' },
  };
  try {
    await axios.post('https://exp.host/--/api/v2/push/send', message, {
      headers: {
        'Accept': 'application/json',
        'Accept-encoding': 'gzip, deflate',
        'Content-Type': 'application/json',
      },
    });
    console.log(`Notification sent to ${token}`);
  } catch (error) {
    console.error('Error sending notification:', error.message);
  }
};

app.post('/register', async (req, res) => {
  const { name, email, password, role, location, notificationToken } = req.body;
  try {
    if (role === 'admin') {
      const adminExists = await User.findOne({ role: 'admin' });
      if (adminExists) return res.status(400).json({ message: 'Admin account already exists.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role,
      location,
      status: role === 'admin' ? 'approved' : 'pending',
      notificationToken,
    });
    await user.save();
    res.status(201).json({
      message: role === 'user' ? 'Your account is pending approval by admin.' : 'Admin registered successfully.',
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.post('/login', async (req, res) => {
  const { email, password, role } = req.body;
  try {
    const user = await User.findOne({ email, role });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    if (user.status === 'pending') return res.status(403).json({ message: 'Account pending approval' });
    if (user.status === 'disapproved') return res.status(403).json({ message: 'Account disapproved' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user._id, name: user.name, role: user.role, points: user.points } });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.post('/scan', authMiddleware, async (req, res) => {
  const { value, location } = req.body;
  const userId = req.user.id;
  try {
    const existingBarcode = await Barcode.findOne({ value });
    if (existingBarcode) return res.status(400).json({ message: 'Barcode expired.' });
    const barcode = new Barcode({ value, userId, location, pointsAwarded: pointsPerScan });
    await barcode.save();
    const user = await User.findById(userId);
    user.points += pointsPerScan;
    await user.save();

    if (user.notificationToken) {
      await sendPushNotification(
        user.notificationToken,
        'Barcode Scanned',
        `You earned ${pointsPerScan} points! Total: ${user.points}`
      );
    }

    res.json({ message: 'Barcode scanned successfully', points: user.points });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.put('/users/:id/status', authMiddleware, adminMiddleware, async (req, res) => {
  const { status } = req.body;
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.status = status;
    await user.save();

    if (user.notificationToken) {
      await sendPushNotification(
        user.notificationToken,
        'Account Status Updated',
        `Your account has been ${status}.`
      );
    }

    res.json({ message: `User ${status} successfully` });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.get('/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.put('/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { name, email, location, points } = req.body;
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.name = name || user.name;
    user.email = email || user.email;
    user.location = location || user.location;
    user.points = points !== undefined ? points : user.points;
    await user.save();
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.delete('/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    await Barcode.deleteMany({ userId: req.params.id }); // Delete user’s barcodes
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.put('/users/:id/reset-points', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.points = 0;
    await user.save();

    if (user.notificationToken) {
      await sendPushNotification(
        user.notificationToken,
        'Points Reset',
        'Your points have been reset by admin.'
      );
    }

    res.json({ message: 'Points reset successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.get('/barcodes', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const barcodes = await Barcode.find().populate('userId', 'name email');
    res.json(barcodes);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.get('/barcodes/user/:userId', authMiddleware, async (req, res) => {
  try {
    const barcodes = await Barcode.find({ userId: req.params.userId });
    res.json(barcodes);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.delete('/barcodes/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const barcode = await Barcode.findByIdAndDelete(req.params.id);
    if (!barcode) return res.status(404).json({ message: 'Barcode not found' });
    res.json({ message: 'Barcode deleted successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.delete('/barcodes', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await Barcode.deleteMany({});
    res.json({ message: 'All barcodes deleted successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.delete('/barcodes/user/:userId', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await Barcode.deleteMany({ userId: req.params.userId });
    res.json({ message: 'User barcodes deleted successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.put('/settings/points-per-scan', authMiddleware, adminMiddleware, async (req, res) => {
  const { points } = req.body;
  try {
    pointsPerScan = points;
    res.json({ message: 'Points per scan updated', pointsPerScan });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.get('/export-barcodes', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const barcodes = await Barcode.find().populate('userId', 'name email');
    const csvWriter = createObjectCsvWriter({
      path: 'barcodes_export.csv',
      header: [
        { id: 'value', title: 'Barcode Value' },
        { id: 'userName', title: 'User Name' },
        { id: 'userEmail', title: 'User Email' },
        { id: 'pointsAwarded', title: 'Points Awarded' },
        { id: 'location', title: 'Location' },
        { id: 'timestamp', title: 'Timestamp' },
      ],
    });

    const records = barcodes.map(barcode => ({
      value: barcode.value,
      userName: barcode.userId.name,
      userEmail: barcode.userId.email,
      pointsAwarded: barcode.pointsAwarded,
      location: barcode.location,
      timestamp: barcode.createdAt.toISOString(),
    }));

    await csvWriter.writeRecords(records);
    res.download('barcodes_export.csv');
  } catch (error) {
    res.status(500).json({ message: 'Failed to export barcodes', error: error.message });
  }
});

// Use Render's assigned PORT
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));