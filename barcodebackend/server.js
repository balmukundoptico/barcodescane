// barcode/barcodebackend/server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { createObjectCsvWriter } = require('csv-writer');
require('dotenv').config();
const User = require('./models/User');
const Barcode = require('./models/Barcode');

const app = express();

// Simplified CORS configuration
app.use(cors({
  origin: 'http://localhost:8081',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json());

// MongoDB Atlas connection
mongoose.connect('mongodb+srv://balmukundoptico:lets12help@job-connector.exb7v.mongodb.net', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(async () => {
    console.log('MongoDB Atlas connected');
    // Ensure single admin exists
    const adminMobile = '7000534581';
    const existingAdmin = await User.findOne({ mobile: adminMobile, role: 'admin' });
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash('krishna123', 10);
      const admin = new User({
        name: 'krishna',
        mobile: adminMobile,
        password: hashedPassword,
        role: 'admin',
        location: 'bhopal',
        status: 'approved',
      });
      await admin.save();
      console.log('Permanent admin created: krishna');
    }
  })
  .catch((err) => console.log('MongoDB Atlas connection error:', err));

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
let pointsPerScan = 50;

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

// Routes
app.post('/register', async (req, res) => {
  const { name, mobile, password, role, location, notificationToken } = req.body;
  try {
    if (role === 'admin') {
      // Block additional admin registration
      const adminExists = await User.findOne({ role: 'admin' });
      if (adminExists) {
        return res.status(403).json({ message: 'Only one admin is allowed. Admin already exists.' });
      }
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      mobile,
      password: hashedPassword,
      role: role === 'admin' ? 'user' : role, // Force non-admin roles
      location,
      status: role === 'admin' ? 'approved' : 'pending',
      notificationToken,
    });
    await user.save();
    res.status(201).json({
      message: role === 'user' ? 'Your account is pending approval by admin.' : 'User registered successfully.',
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.post('/login', async (req, res) => {
  const { mobile, password, role } = req.body;
  try {
    const user = await User.findOne({ mobile, role });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    if (user.status === 'pending') return res.status(403).json({ message: 'Account pending approval' });
    if (user.status === 'disapproved') return res.status(403).json({ message: 'Account disapproved' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user._id, name: user.name, role: user.role, points: user.points, mobile: user.mobile, location: user.location, status: user.status } });
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
    if (user.mobile === '7000534581' && user.role === 'admin') {
      return res.status(403).json({ message: 'Cannot modify permanent admin status.' });
    }
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
  const { name, mobile, location, points } = req.body;
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.mobile === '7000534581' && user.role === 'admin') {
      return res.status(403).json({ message: 'Cannot modify permanent admin.' });
    }
    user.name = name || user.name;
    user.mobile = mobile || user.mobile;
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
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.mobile === '7000534581' && user.role === 'admin') {
      return res.status(403).json({ message: 'Cannot delete permanent admin.' });
    }
    await User.findByIdAndDelete(req.params.id);
    await Barcode.deleteMany({ userId: req.params.id });
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.put('/users/:id/reset-points', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.mobile === '7000534581' && user.role === 'admin') {
      return res.status(403).json({ message: 'Cannot reset points of permanent admin.' });
    }
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
    const barcodes = await Barcode.find().populate('userId', 'name mobile');
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

app.get('/settings/points-per-scan', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    res.json({ points: pointsPerScan });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.put('/settings/barcode-range', authMiddleware, adminMiddleware, async (req, res) => {
  const { start, end } = req.body;
  try {
    // Assuming barcode range is stored globally or in a settings collection
    // For simplicity, we'll store it in memory (not persistent)
    global.barcodeRange = { start, end };
    res.json({ message: 'Barcode range updated', start, end });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.get('/settings/barcode-range', authMiddleware, async (req, res) => {
  try {
    res.json(global.barcodeRange || { start: '0', end: '9999999999999' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.get('/export-barcodes', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const barcodes = await Barcode.find().populate('userId', 'name mobile');
    const csvWriter = createObjectCsvWriter({
      path: 'barcodes_export.csv',
      header: [
        { id: 'value', title: 'Barcode Value' },
        { id: 'userName', title: 'User Name' },
        { id: 'userMobile', title: 'User Mobile' },
        { id: 'pointsAwarded', title: 'Points Awarded' },
        { id: 'location', title: 'Location' },
        { id: 'timestamp', title: 'Timestamp' },
      ],
    });

    const records = barcodes.map(barcode => ({
      value: barcode.value,
      userName: barcode.userId.name,
      userMobile: barcode.userId.mobile,
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));