const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'your_jwt_secret_key'; // Change this to a strong secret in production
const nodemailer = require('nodemailer');
const cron = require('node-cron');

const app = express();
app.use(cors());
app.use(express.json());

// Connect to MongoDB
// mongodb+srv://shubham:XEhbqsmjt4cnACyz@cluster0.ewetbgm.mongodb.net/
mongoose.connect('mongodb+srv://asitkushel:oecqfOYACIL2NPMd@cluster0.sq7fni5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('MongoDB connected');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

app.get("/",(req,res)=>{
  res.send("hlw worlld")
})

// Import Product model
const Product = require('./model/Product');
const User = require('./model/User');
const bcrypt = require('bcrypt');
const Configuration = require('./model/Configuration');

// Auth middleware
function auth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.userId = decoded.userId;
    next();
  });
}

// POST endpoint to save product customization
app.post('/api/save-product', async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json({ message: 'Product saved successfully!', product });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save product', details: err });
  }
});

// GET endpoint to fetch all products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({});
    res.status(200).json(products);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch products', details: err });
  }
});

// GET endpoint to fetch a specific product by ID
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.status(200).json(product);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch product', details: err });
  }
});

// Login API endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }
    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }
    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });
    res.status(200).json({ message: 'Login successful', token, user: { name: user.name, email: user.email, phone: user.phone, _id: user._id, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Server error', details: err });
  }
});

// Nodemailer transporter setup (replace with real credentials in production)
const transporter = nodemailer.createTransport({
  host: 'smtpout.secureserver.net',
  port: 465,
  secure: true, // true for 465, false for other ports
  auth: {
    user: 'info@kusheldigi.com',
    pass: 'Kusheldigiinfopass',
  },
  from: 'info@kusheldigi.com',
  tls: {
    rejectUnauthorized: false,
  },
});

// User registration API endpoint (only superadmin)
app.post('/api/register', auth, async (req, res) => {
  try {
    // Only superadmin can register users
    const currentUser = await User.findById(req.userId);
    if (!currentUser || currentUser.role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can register users.' });
    }
    const { name, email, password, phone, role } = req.body;
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      phone,
      role: role || 'user',
      active: true
    });
    await newUser.save();
    // Send onboarding email
    await transporter.sendMail({
      from: 'info@kusheldigi.com',
      to: newUser.email,
      subject: 'Welcome to the Platform',
      html: `<h2>Welcome, ${newUser.name}!</h2><p>Your account has been created.</p><p><b>Email:</b> ${newUser.email}<br/><b>Password:</b> ${password}</p><p>Please login and change your password after first login.</p>`
    });
    res.status(201).json({ message: 'User registered successfully', user: { name: newUser.name, email: newUser.email, phone: newUser.phone, role: newUser.role } });
  } catch (err) {
    res.status(500).json({ error: 'Server error', details: err });
  }
});

// CRON JOB: Deactivate subscription after trial
cron.schedule('0 0 * * *', async () => {
  // Runs every day at midnight
  const now = new Date();
  await User.updateMany({ trialEndsAt: { $lte: now }, subscription: 'active' }, { $set: { subscription: 'inactive' } });
});

// Get all users (superadmin only)
app.get('/api/users', auth, async (req, res) => {
  try {
    const currentUser = await User.findById(req.userId);
    if (!currentUser || currentUser.role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can view users.' });
    }
    const users = await User.find({}, '-password');
    res.status(200).json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users', details: err });
  }
});

// Update user (superadmin only)
app.put('/api/users/:id', auth, async (req, res) => {
  try {
    const currentUser = await User.findById(req.userId);
    if (!currentUser || currentUser.role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can update users.' });
    }
    const { name, email, phone, password } = req.body;
    const update = { name, email, phone };
    let passwordChanged = false;
    if (password) {
      update.password = await bcrypt.hash(password, 10);
      passwordChanged = true;
    }
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: update },
      { new: true, select: '-password' }
    );
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    // Send onboarding email if password changed or email changed
    if (passwordChanged || (email && email !== user.email)) {
      await transporter.sendMail({
        from: 'info@kusheldigi.com',
        to: user.email,
        subject: 'Your Account Updated',
        html: `<h2>Hello, ${user.name}!</h2><p>Your account details have been updated.</p><p><b>Email:</b> ${user.email}<br/>${passwordChanged ? `<b>New Password:</b> ${password}` : ''}</p>`
      });
    }
    res.status(200).json({ message: 'User updated successfully', user });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user', details: err });
  }
});
// Activate/Deactivate user (superadmin only)
app.patch('/api/users/:id/active', auth, async (req, res) => {
  try {
    const currentUser = await User.findById(req.userId);
    if (!currentUser || currentUser.role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can change user status.' });
    }
    const { active } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { active } },
      { new: true, select: '-password' }
    );
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json({ message: `User ${active ? 'activated' : 'deactivated'} successfully`, user });
  } catch (err) {
    res.status(500).json({ error: 'Failed to change user status', details: err });
  }
});

// Delete user (superadmin only)
app.delete('/api/users/:id', auth, async (req, res) => {
  try {
    const currentUser = await User.findById(req.userId);
    if (!currentUser || currentUser.role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can delete users.' });
    }
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json({ message: 'User deleted successfully', email: user.email });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user', details: err });
  }
});

// Create Configuration
app.post('/api/configurations', auth, async (req, res) => {
  try {
    // Check if user already has a configuration
    const existingConfig = await Configuration.findOne({ user: req.userId });
    if (existingConfig) {
      return res.status(429).json({ error: 'You can only create one configuration.' });
    }
    // Set trialEndsAt to 7 days from now and subscription to 'active'
    const now = new Date();
    const trialEndsAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    const config = new Configuration({
      storeId: req.body.storeId,
      storeUrl: req.body.storeUrl,
      storeAccessToken: req.body.storeAccessToken,
      storeEndpoint: req.body.storeEndpoint,
      subscription: 'active',
      trialEndsAt,
      user: req.userId
    });
    await config.save();
    res.status(201).json({ message: 'Configuration saved successfully!', config });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save configuration', details: err });
  }
});

// Get all Configurations
app.get('/api/configurations', auth, async (req, res) => {
  try {
    const configs = await Configuration.find({ user: req.userId });
    res.status(200).json(configs);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch configurations', details: err });
  }
});

// Get Configuration by ID
app.get('/api/configurations/:id', auth, async (req, res) => {
  try {
    const config = await Configuration.findOne({ _id: req.params.id, user: req.userId });
    if (!config) {
      return res.status(404).json({ error: 'Configuration not found' });
    }
    res.status(200).json(config);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch configuration', details: err });
  }
});

// Update Configuration by ID
app.put('/api/configurations/:id', auth, async (req, res) => {
  try {
    const update = {
      storeId: req.body.storeId,
      storeUrl: req.body.storeUrl,
      storeAccessToken: req.body.storeAccessToken,
      storeEndpoint: req.body.storeEndpoint,
      subscription: req.body.subscription
    };
    const config = await Configuration.findOneAndUpdate({ _id: req.params.id, user: req.userId }, update, { new: true });
    if (!config) {
      return res.status(404).json({ error: 'Configuration not found' });
    }
    res.status(200).json({ message: 'Configuration updated successfully!', config });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update configuration', details: err });
  }
});

// Delete Configuration by ID
app.delete('/api/configurations/:id', auth, async (req, res) => {
  try {
    const config = await Configuration.findOneAndDelete({ _id: req.params.id, user: req.userId });
    if (!config) {
      return res.status(404).json({ error: 'Configuration not found' });
    }
    res.status(200).json({ message: 'Configuration deleted successfully!' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete configuration', details: err });
  }
});

// Get all configurations for a specific user
app.get('/api/user/:userId/configurations', async (req, res) => {
  try {
    const configs = await Configuration.find({ user: req.params.userId });
    res.status(200).json(configs);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user configurations', details: err });
  }
});

// CRON JOB: Deactivate configuration subscription after trial
cron.schedule('0 1 * * *', async () => {
  // Runs every day at 1am
  const now = new Date();
  await Configuration.updateMany({ trialEndsAt: { $lte: now }, subscription: 'active' }, { $set: { subscription: 'inactive' } });
});

// Get configuration validity by storeId
app.get('/api/configuration/by-store/:storeId', async (req, res) => {
  try {
    const config = await Configuration.findOne({ storeId: req.params.storeId });
    if (!config) {
      return res.status(404).json({ subscribe: false });
    }
    if (config.subscription === 'active') {
      return res.json({ subscribe: true });
    } else {
      return res.json({ subscribe: false });
    }
  } catch (err) {
    res.status(500).json({ subscribe: false });
  }
});

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 