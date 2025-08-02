const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'your_jwt_secret_key'; // Change this to a strong secret in production
const nodemailer = require('nodemailer');
const cron = require('node-cron');
require('dotenv').config();
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });
const bcrypt = require('bcrypt');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const app = express();
app.use(cors());
app.use(express.json());

// MySQL Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'kusheldigi_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
});

// Database Tables Creation
const createTables = async () => {
  try {
    const connection = await pool.getConnection();
    
    // Users table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        phone VARCHAR(20),
        role ENUM('user', 'admin', 'superadmin') DEFAULT 'user',
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Products table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        product_data JSON NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Configurations table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS configurations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        store_id VARCHAR(255) NOT NULL,
        store_url TEXT,
        store_access_token TEXT,
        store_endpoint TEXT,
        subscription ENUM('active', 'inactive') DEFAULT 'active',
        trial_ends_at DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY unique_user_config (user_id)
      )
    `);

    // Layer Designs table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS layer_designs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        sq VARCHAR(255) NOT NULL,
        design_name VARCHAR(255) NOT NULL,
        layers_design JSON,
        customizable_data JSON DEFAULT ('[]'),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Create default superadmin user if not exists
    const [existingUsers] = await connection.execute('SELECT id FROM users WHERE role = "superadmin" LIMIT 1');
    if (existingUsers.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await connection.execute(`
        INSERT INTO users (name, email, password, role, active) 
        VALUES (?, ?, ?, 'superadmin', TRUE)
      `, ['Super Admin', 'admin@kusheldigi.com', hashedPassword]);
      console.log('Default superadmin created: admin@kusheldigi.com / admin123');
    }

    connection.release();
    console.log('MySQL tables created successfully');
  } catch (error) {
    console.error('Error creating tables:', error);
  }
};

// Initialize database
createTables();

// Test endpoint to add sample data
app.post('/api/test/add-design', async (req, res) => {
  try {
    const sampleLayersDesign = {
      layers: [
        {
          id: 1,
          name: "Background",
          type: "image",
          url: "https://cloudinary.com/image1.jpg",
          position: { x: 0, y: 0 },
          size: { width: 500, height: 300 }
        },
        {
          id: 2,
          name: "Text Layer",
          type: "text",
          content: "Custom Text",
          font: "Arial",
          color: "#000000",
          position: { x: 100, y: 50 }
        },
        {
          id: 3,
          name: "Logo",
          type: "image",
          url: "https://cloudinary.com/logo.jpg",
          position: { x: 200, y: 150 },
          size: { width: 100, height: 100 }
        }
      ],
      canvas: {
        width: 800,
        height: 600,
        background: "#ffffff"
      }
    };

    const [result] = await pool.execute(
      'INSERT INTO layer_designs (user_id, sq, design_name, layers_design, customizable_data) VALUES (?, ?, ?, ?, ?)',
      [1, 'shirt', 'Sample Design with Layers', JSON.stringify(sampleLayersDesign), JSON.stringify([])]
    );
    res.json({ message: 'Test design with layers added', id: result.insertId, layersDesign: sampleLayersDesign });
  } catch (err) {
    res.status(500).json({ error: 'Failed to add test design', details: err.message });
  }
});

// Update existing design with sample layers
app.post('/api/test/update-design/:id', async (req, res) => {
  try {
    const sampleLayersDesign = {
      layers: [
        {
          id: 1,
          name: "Background",
          type: "image",
          url: "https://cloudinary.com/image1.jpg",
          position: { x: 0, y: 0 },
          size: { width: 500, height: 300 }
        },
        {
          id: 2,
          name: "Text Layer",
          type: "text",
          content: "Custom Text",
          font: "Arial",
          color: "#000000",
          position: { x: 100, y: 50 }
        },
        {
          id: 3,
          name: "Logo",
          type: "image",
          url: "https://cloudinary.com/logo.jpg",
          position: { x: 200, y: 150 },
          size: { width: 100, height: 100 }
        }
      ],
      canvas: {
        width: 800,
        height: 600,
        background: "#ffffff"
      }
    };

    const [result] = await pool.execute(
      'UPDATE layer_designs SET layers_design = ? WHERE id = ?',
      [JSON.stringify(sampleLayersDesign), req.params.id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Design not found' });
    }
    
    res.json({ message: 'Design updated with sample layers', layersDesign: sampleLayersDesign });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update design', details: err.message });
  }
});

app.get("/", (req, res) => {
  res.send("Hello World - MySQL Version");
});

// OTP storage (in production, use Redis or database table)
const otpStore = new Map();

// Generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
  host: 'smtpout.secureserver.net',
  port: 465,
  secure: true,
  auth: {
    user: 'info@kusheldigi.com',
    pass: 'Kusheldigiinfopass',
  },
  from: 'info@kusheldigi.com',
  tls: {
    rejectUnauthorized: false,
  },
});

// Send OTP via email
async function sendOTP(email, otp) {
  try {
    await transporter.sendMail({
      from: 'info@kusheldigi.com',
      to: email,
      subject: 'Login OTP Verification',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333; text-align: center;">Login Verification</h2>
          <p style="color: #666; font-size: 16px;">Your login verification code is:</p>
          <div style="background: #f8f9fa; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
            <h1 style="color: #007bff; font-size: 32px; margin: 0; letter-spacing: 5px;">${otp}</h1>
          </div>
          <p style="color: #666; font-size: 14px;">This code will expire in 10 minutes.</p>
          <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px;">If you didn't request this code, please ignore this email.</p>
        </div>
      `
    });
    return true;
  } catch (error) {
    console.error('Email sending error:', error);
    return false;
  }
}

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

// Helper middleware to check for superadmin
async function requireSuperAdmin(req, res, next) {
  try {
    const [users] = await pool.execute('SELECT role FROM users WHERE id = ?', [req.userId]);
    if (users.length === 0 || users[0].role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can perform this action' });
    }
    next();
  } catch (error) {
    res.status(403).json({ error: 'Only superadmin can perform this action' });
  }
}

// PRODUCT ENDPOINTS
// POST endpoint to save product customization
app.post('/api/save-product', async (req, res) => {
  try {
    const [result] = await pool.execute(
      'INSERT INTO products (product_data) VALUES (?)',
      [JSON.stringify(req.body)]
    );
    res.status(201).json({ 
      message: 'Product saved successfully!', 
      product: { id: result.insertId, ...req.body } 
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save product', details: err.message });
  }
});

// GET endpoint to fetch all products
app.get('/api/products', async (req, res) => {
  try {
    const [products] = await pool.execute('SELECT * FROM products ORDER BY created_at DESC');
    const formattedProducts = products.map(product => ({
      id: product.id,
      ...JSON.parse(product.product_data),
      created_at: product.created_at,
      updated_at: product.updated_at
    }));
    res.status(200).json(formattedProducts);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch products', details: err.message });
  }
});

// GET endpoint to fetch a specific product by ID
app.get('/api/products/:id', async (req, res) => {
  try {
    const [products] = await pool.execute('SELECT * FROM products WHERE id = ?', [req.params.id]);
    if (products.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    const product = {
      id: products[0].id,
      ...JSON.parse(products[0].product_data),
      created_at: products[0].created_at,
      updated_at: products[0].updated_at
    };
    res.status(200).json(product);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch product', details: err.message });
  }
});

// AUTH ENDPOINTS
// Request OTP for login
app.post('/api/request-otp', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    // First verify email and password
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }
    
    const user = users[0];
    
    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Check if user is active
    if (!user.active) {
      return res.status(400).json({ error: 'Account is deactivated. Please contact administrator.' });
    }

    // Generate OTP
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Store OTP with expiry
    otpStore.set(email, {
      otp,
      expiry: otpExpiry,
      userId: user.id
    });

    // Send OTP via email
    const emailSent = await sendOTP(email, otp);
    if (!emailSent) {
      return res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
    }

    res.status(200).json({ 
      message: 'OTP sent successfully to your email',
      email: email 
    });

  } catch (err) {
    console.error('OTP request error:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// Verify OTP and complete login
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  
  try {
    const storedData = otpStore.get(email);
    
    if (!storedData) {
      return res.status(400).json({ error: 'OTP expired or not found. Please request a new OTP.' });
    }

    // Check if OTP is expired
    if (new Date() > storedData.expiry) {
      otpStore.delete(email);
      return res.status(400).json({ error: 'OTP has expired. Please request a new OTP.' });
    }

    // Verify OTP
    if (storedData.otp !== otp) {
      return res.status(400).json({ error: 'Invalid OTP. Please try again.' });
    }

    // Get user data
    const [users] = await pool.execute('SELECT * FROM users WHERE id = ?', [storedData.userId]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'User not found' });
    }

    const user = users[0];

    // Generate JWT token
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1d' });
    
    // Clear OTP from store
    otpStore.delete(email);

    res.status(200).json({ 
      message: 'Login successful', 
      token, 
      user: { 
        name: user.name, 
        email: user.email, 
        phone: user.phone, 
        id: user.id, 
        role: user.role 
      } 
    });

  } catch (err) {
    console.error('OTP verification error:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// Clean expired OTPs every 5 minutes
setInterval(() => {
  const now = new Date();
  for (const [email, data] of otpStore.entries()) {
    if (now > data.expiry) {
      otpStore.delete(email);
    }
  }
}, 5 * 60 * 1000);

// Login API endpoint (now deprecated - use OTP flow instead)
app.post('/api/login', async (req, res) => {
  res.status(400).json({ 
    error: 'Please use OTP verification. Use /api/request-otp first, then /api/verify-otp.' 
  });
});

// USER MANAGEMENT ENDPOINTS
// User registration API endpoint (only superadmin)
app.post('/api/register', auth, async (req, res) => {
  try {
    // Only superadmin can register users
    const [currentUsers] = await pool.execute('SELECT role FROM users WHERE id = ?', [req.userId]);
    if (currentUsers.length === 0 || currentUsers[0].role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can register users.' });
    }

    const { name, email, password, phone, role } = req.body;
    
    // Check if user already exists
    const [existingUsers] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const [result] = await pool.execute(
      'INSERT INTO users (name, email, password, phone, role, active) VALUES (?, ?, ?, ?, ?, TRUE)',
      [name, email, hashedPassword, phone, role || 'user']
    );

    // Send onboarding email
    await transporter.sendMail({
      from: 'info@kusheldigi.com',
      to: email,
      subject: 'Welcome to the Platform',
      html: `<h2>Welcome, ${name}!</h2><p>Your account has been created.</p><p><b>Email:</b> ${email}<br/><b>Password:</b> ${password}</p><p>Please login and change your password after first login.</p>`
    });

    res.status(201).json({ 
      message: 'User registered successfully', 
      user: { id: result.insertId, name, email, phone, role: role || 'user' } 
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// Get all users (superadmin only)
app.get('/api/users', auth, async (req, res) => {
  try {
    const [currentUsers] = await pool.execute('SELECT role FROM users WHERE id = ?', [req.userId]);
    if (currentUsers.length === 0 || currentUsers[0].role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can view users.' });
    }

    const [users] = await pool.execute('SELECT id, name, email, phone, role, active, created_at, updated_at FROM users');
    res.status(200).json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users', details: err.message });
  }
});

// Update user (superadmin only)
app.put('/api/users/:id', auth, async (req, res) => {
  try {
    const [currentUsers] = await pool.execute('SELECT role FROM users WHERE id = ?', [req.userId]);
    if (currentUsers.length === 0 || currentUsers[0].role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can update users.' });
    }

    const { name, email, phone, password } = req.body;
    let query = 'UPDATE users SET name = ?, email = ?, phone = ?';
    let params = [name, email, phone];
    let passwordChanged = false;

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      query += ', password = ?';
      params.push(hashedPassword);
      passwordChanged = true;
    }

    query += ' WHERE id = ?';
    params.push(req.params.id);

    await pool.execute(query, params);

    const [users] = await pool.execute(
      'SELECT id, name, email, phone, role, active, created_at, updated_at FROM users WHERE id = ?', 
      [req.params.id]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = users[0];

    // Send update email if password changed
    if (passwordChanged) {
      await transporter.sendMail({
        from: 'info@kusheldigi.com',
        to: user.email,
        subject: 'Your Account Updated',
        html: `<h2>Hello, ${user.name}!</h2><p>Your account details have been updated.</p><p><b>Email:</b> ${user.email}<br/><b>New Password:</b> ${password}</p>`
      });
    }

    res.status(200).json({ message: 'User updated successfully', user });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user', details: err.message });
  }
});

// Activate/Deactivate user (superadmin only)
app.patch('/api/users/:id/active', auth, async (req, res) => {
  try {
    const [currentUsers] = await pool.execute('SELECT role FROM users WHERE id = ?', [req.userId]);
    if (currentUsers.length === 0 || currentUsers[0].role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can change user status.' });
    }

    const { active } = req.body;
    await pool.execute('UPDATE users SET active = ? WHERE id = ?', [active, req.params.id]);

    const [users] = await pool.execute(
      'SELECT id, name, email, phone, role, active, created_at, updated_at FROM users WHERE id = ?', 
      [req.params.id]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({ 
      message: `User ${active ? 'activated' : 'deactivated'} successfully`, 
      user: users[0] 
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to change user status', details: err.message });
  }
});

// Delete user (superadmin only)
app.delete('/api/users/:id', auth, async (req, res) => {
  try {
    const [currentUsers] = await pool.execute('SELECT role FROM users WHERE id = ?', [req.userId]);
    if (currentUsers.length === 0 || currentUsers[0].role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can delete users.' });
    }

    const [users] = await pool.execute('SELECT email FROM users WHERE id = ?', [req.params.id]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    await pool.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.status(200).json({ message: 'User deleted successfully', email: users[0].email });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user', details: err.message });
  }
});

// CONFIGURATION ENDPOINTS
// Create Configuration
app.post('/api/configurations', auth, async (req, res) => {
  try {
    // Check if user already has a configuration
    const [existingConfigs] = await pool.execute('SELECT id FROM configurations WHERE user_id = ?', [req.userId]);
    if (existingConfigs.length > 0) {
      return res.status(429).json({ error: 'You can only create one configuration.' });
    }

    // Set trialEndsAt to 7 days from now
    const now = new Date();
    const trialEndsAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

    const [result] = await pool.execute(
      'INSERT INTO configurations (user_id, store_id, store_url, store_access_token, store_endpoint, subscription, trial_ends_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [req.userId, req.body.storeId, req.body.storeUrl, req.body.storeAccessToken, req.body.storeEndpoint, 'active', trialEndsAt]
    );

    const [configs] = await pool.execute('SELECT * FROM configurations WHERE id = ?', [result.insertId]);
    res.status(201).json({ message: 'Configuration saved successfully!', config: configs[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save configuration', details: err.message });
  }
});

// Get all Configurations
app.get('/api/configurations', auth, async (req, res) => {
  try {
    const [configs] = await pool.execute('SELECT * FROM configurations WHERE user_id = ?', [req.userId]);
    res.status(200).json(configs);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch configurations', details: err.message });
  }
});

// Get Configuration by ID
app.get('/api/configurations/:id', auth, async (req, res) => {
  try {
    const [configs] = await pool.execute('SELECT * FROM configurations WHERE id = ? AND user_id = ?', [req.params.id, req.userId]);
    if (configs.length === 0) {
      return res.status(404).json({ error: 'Configuration not found' });
    }
    res.status(200).json(configs[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch configuration', details: err.message });
  }
});

// Update Configuration by ID
app.put('/api/configurations/:id', auth, async (req, res) => {
  try {
    await pool.execute(
      'UPDATE configurations SET store_id = ?, store_url = ?, store_access_token = ?, store_endpoint = ?, subscription = ? WHERE id = ? AND user_id = ?',
      [req.body.storeId, req.body.storeUrl, req.body.storeAccessToken, req.body.storeEndpoint, req.body.subscription, req.params.id, req.userId]
    );

    const [configs] = await pool.execute('SELECT * FROM configurations WHERE id = ? AND user_id = ?', [req.params.id, req.userId]);
    if (configs.length === 0) {
      return res.status(404).json({ error: 'Configuration not found' });
    }

    res.status(200).json({ message: 'Configuration updated successfully!', config: configs[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update configuration', details: err.message });
  }
});

// Delete Configuration by ID
app.delete('/api/configurations/:id', auth, async (req, res) => {
  try {
    const [result] = await pool.execute('DELETE FROM configurations WHERE id = ? AND user_id = ?', [req.params.id, req.userId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Configuration not found' });
    }
    res.status(200).json({ message: 'Configuration deleted successfully!' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete configuration', details: err.message });
  }
});

// Get all configurations for a specific user
app.get('/api/user/:userId/configurations', async (req, res) => {
  try {
    const [configs] = await pool.execute('SELECT * FROM configurations WHERE user_id = ?', [req.params.userId]);
    res.status(200).json(configs);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user configurations', details: err.message });
  }
});

// Get configuration validity by storeId
app.get('/api/configuration/by-store/:storeId', async (req, res) => {
  try {
    const [configs] = await pool.execute('SELECT subscription FROM configurations WHERE store_id = ?', [req.params.storeId]);
    if (configs.length === 0) {
      return res.status(404).json({ subscribe: false });
    }
    if (configs[0].subscription === 'active') {
      return res.json({ subscribe: true });
    } else {
      return res.json({ subscribe: false });
    }
  } catch (err) {
    res.status(500).json({ subscribe: false });
  }
});

// LAYER DESIGN ENDPOINTS
// List all unique SQs for the user
app.get('/api/layerdesigns/sqs', auth, requireSuperAdmin, async (req, res) => {
  try {
    const [sqs] = await pool.execute('SELECT DISTINCT sq FROM layer_designs WHERE user_id = ?', [req.userId]);
    res.json(sqs.map(row => row.sq));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch SQs', details: err.message });
  }
});

// List LayerDesigns by SQ
app.get('/api/layerdesigns/by-sq/:sq', auth, requireSuperAdmin, async (req, res) => {
  try {
    console.log('Fetching designs for SQ:', req.params.sq, 'User ID:', req.userId);
    const [layerDesigns] = await pool.execute('SELECT * FROM layer_designs WHERE user_id = ? AND sq = ?', [req.userId, req.params.sq]);
    console.log('Raw designs from DB:', layerDesigns);
    const formattedDesigns = layerDesigns.map(design => ({
      ...design,
      designName: design.design_name,
      layersDesign: JSON.parse(design.layers_design || 'null'),
      customizableData: JSON.parse(design.customizable_data || '[]')
    }));
    console.log('Formatted designs:', formattedDesigns);
    res.json(formattedDesigns);
  } catch (err) {
    console.error('Error in by-sq endpoint:', err);
    res.status(500).json({ error: 'Failed to fetch LayerDesigns', details: err.message });
  }
});

// Create a new LayerDesign
app.post('/api/layerdesigns', auth, requireSuperAdmin, async (req, res) => {
  try {
    const { sq, designName, layersDesign } = req.body;
    const [result] = await pool.execute(
      'INSERT INTO layer_designs (user_id, sq, design_name, layers_design, customizable_data) VALUES (?, ?, ?, ?, ?)',
      [req.userId, sq, designName, JSON.stringify(layersDesign), JSON.stringify([])]
    );

    const [layerDesigns] = await pool.execute('SELECT * FROM layer_designs WHERE id = ?', [result.insertId]);
    const layerDesign = {
      ...layerDesigns[0],
      designName: layerDesigns[0].design_name,
      layersDesign: JSON.parse(layerDesigns[0].layers_design || 'null'),
      customizableData: JSON.parse(layerDesigns[0].customizable_data || '[]')
    };

    res.status(201).json({ message: 'LayerDesign created', layerDesign });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create LayerDesign', details: err.message });
  }
});

// Get all LayerDesigns for the logged-in user
app.get('/api/layerdesigns', auth, requireSuperAdmin, async (req, res) => {
  try {
    const [layerDesigns] = await pool.execute('SELECT * FROM layer_designs WHERE user_id = ?', [req.userId]);
    const formattedDesigns = layerDesigns.map(design => ({
      ...design,
      designName: design.design_name,
      layersDesign: JSON.parse(design.layers_design || 'null'),
      customizableData: JSON.parse(design.customizable_data || '[]')
    }));
    res.json(formattedDesigns);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch LayerDesigns', details: err.message });
  }
});

// Get a single LayerDesign by ID
app.get('/api/layerdesigns/:id', auth, requireSuperAdmin, async (req, res) => {
  try {
    const [layerDesigns] = await pool.execute('SELECT * FROM layer_designs WHERE id = ? AND user_id = ?', [req.params.id, req.userId]);
    if (layerDesigns.length === 0) {
      return res.status(404).json({ error: 'LayerDesign not found' });
    }

    const layerDesign = {
      ...layerDesigns[0],
      designName: layerDesigns[0].design_name,
      layersDesign: JSON.parse(layerDesigns[0].layers_design || 'null'),
      customizableData: JSON.parse(layerDesigns[0].customizable_data || '[]')
    };

    res.json(layerDesign);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch LayerDesign', details: err.message });
  }
});

// Bulk update SQ for all LayerDesigns
app.put('/api/layerdesigns/bulk-update-sq', auth, requireSuperAdmin, async (req, res) => {
  try {
    const { oldSq, newSq } = req.body;
    const [result] = await pool.execute(
      'UPDATE layer_designs SET sq = ? WHERE user_id = ? AND sq = ?', 
      [newSq, req.userId, oldSq]
    );
    res.json({ message: 'SQ updated', modifiedCount: result.affectedRows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update SQ', details: err.message });
  }
});

// Bulk delete LayerDesigns by SQ
app.delete('/api/layerdesigns/by-sq/:sq', auth, requireSuperAdmin, async (req, res) => {
  try {
    const [result] = await pool.execute('DELETE FROM layer_designs WHERE user_id = ? AND sq = ?', [req.userId, req.params.sq]);
    res.json({ message: 'LayerDesigns deleted', deletedCount: result.affectedRows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete LayerDesigns', details: err.message });
  }
});

// Update a LayerDesign (edit design name, sq, or layersDesign)
app.put('/api/layerdesigns/:id', auth, requireSuperAdmin, async (req, res) => {
  try {
    const { sq, designName, layersDesign, customizableData } = req.body;
    
    let query = 'UPDATE layer_designs SET sq = ?, design_name = ?, layers_design = ?';
    let params = [sq, designName, JSON.stringify(layersDesign)];
    
    if (customizableData) {
      query += ', customizable_data = ?';
      params.push(JSON.stringify(customizableData));
    }
    
    query += ' WHERE id = ? AND user_id = ?';
    params.push(req.params.id, req.userId);

    const [result] = await pool.execute(query, params);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'LayerDesign not found' });
    }

    const [layerDesigns] = await pool.execute('SELECT * FROM layer_designs WHERE id = ?', [req.params.id]);
    const layerDesign = {
      ...layerDesigns[0],
      designName: layerDesigns[0].design_name,
      layersDesign: JSON.parse(layerDesigns[0].layers_design || 'null'),
      customizableData: JSON.parse(layerDesigns[0].customizable_data || '[]')
    };

    res.json({ message: 'LayerDesign updated', layerDesign });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update LayerDesign', details: err.message });
  }
});

// Delete a LayerDesign
app.delete('/api/layerdesigns/:id', auth, requireSuperAdmin, async (req, res) => {
  try {
    const [result] = await pool.execute('DELETE FROM layer_designs WHERE id = ? AND user_id = ?', [req.params.id, req.userId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'LayerDesign not found' });
    }
    res.json({ message: 'LayerDesign deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete LayerDesign', details: err.message });
  }
});

// Add customizable data to a LayerDesign
app.post('/api/layerdesigns/:id/customize', auth, requireSuperAdmin, async (req, res) => {
  try {
    const { title, shortDescription, files } = req.body;
    
    // Get current customizable data
    const [layerDesigns] = await pool.execute('SELECT customizable_data FROM layer_designs WHERE id = ? AND user_id = ?', [req.params.id, req.userId]);
    if (layerDesigns.length === 0) {
      return res.status(404).json({ error: 'LayerDesign not found' });
    }

    const currentData = JSON.parse(layerDesigns[0].customizable_data || '[]');
    currentData.push({ title, shortDescription, files });

    await pool.execute(
      'UPDATE layer_designs SET customizable_data = ? WHERE id = ? AND user_id = ?',
      [JSON.stringify(currentData), req.params.id, req.userId]
    );

    const [updatedDesigns] = await pool.execute('SELECT * FROM layer_designs WHERE id = ?', [req.params.id]);
    const layerDesign = {
      ...updatedDesigns[0],
      designName: updatedDesigns[0].design_name,
      layersDesign: JSON.parse(updatedDesigns[0].layers_design || 'null'),
      customizableData: JSON.parse(updatedDesigns[0].customizable_data || '[]')
    };

    res.json({ message: 'Customizable data added', layerDesign });
  } catch (err) {
    res.status(500).json({ error: 'Failed to add customizable data', details: err.message });
  }
});

// UPLOAD ENDPOINT
app.post('/api/upload', auth, requireSuperAdmin, upload.single('image'), async (req, res) => {
  try {
    const stream = cloudinary.uploader.upload_stream(
      { folder: 'customizer' },
      (error, result) => {
        if (error) return res.status(500).json({ error: 'Cloudinary upload failed', details: error });
        res.json({ url: result.secure_url });
      }
    );
    stream.end(req.file.buffer);
  } catch (err) {
    res.status(500).json({ error: 'Upload failed', details: err.message });
  }
});

// PASSWORD RESET ENDPOINTS
// Forgot password - Request reset
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  try {
    // Check if user exists
    const [users] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'No account found with this email address' });
    }

    const user = users[0];

    // Check if user is active
    if (!user.active) {
      return res.status(400).json({ error: 'Account is deactivated. Please contact administrator.' });
    }

    // Generate reset token
    const resetToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
    
    // Store reset token with expiry
    otpStore.set(`reset_${email}`, {
      token: resetToken,
      expiry: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
      userId: user.id
    });

    // Create reset link
    const resetLink = `http://localhost:5173/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`;

    // Send reset email
    const emailSent = await transporter.sendMail({
      from: 'info@kusheldigi.com',
      to: email,
      subject: 'Password Reset Request',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333; text-align: center;">Password Reset Request</h2>
          <p style="color: #666; font-size: 16px;">Hello ${user.name},</p>
          <p style="color: #666; font-size: 16px;">You have requested to reset your password. Click the button below to reset your password:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetLink}" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Reset Password</a>
          </div>
          <p style="color: #666; font-size: 14px;">This link will expire in 1 hour.</p>
          <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px;">If you didn't request this password reset, please ignore this email.</p>
        </div>
      `
    });

    if (!emailSent) {
      return res.status(500).json({ error: 'Failed to send reset email. Please try again.' });
    }

    res.status(200).json({ 
      message: 'Password reset link sent to your email',
      email: email 
    });

  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// Verify reset token
app.post('/api/verify-reset-token', async (req, res) => {
  const { token, email } = req.body;
  
  try {
    const storedData = otpStore.get(`reset_${email}`);
    
    if (!storedData) {
      return res.status(400).json({ error: 'Reset link expired or not found.' });
    }

    // Check if token is expired
    if (new Date() > storedData.expiry) {
      otpStore.delete(`reset_${email}`);
      return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });
    }

    // Verify token
    if (storedData.token !== token) {
      return res.status(400).json({ error: 'Invalid reset link.' });
    }

    res.status(200).json({ 
      message: 'Token verified successfully',
      valid: true
    });

  } catch (err) {
    console.error('Token verification error:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// Reset password
app.post('/api/reset-password', async (req, res) => {
  const { token, email, newPassword, confirmPassword } = req.body;
  
  try {
    // Validate passwords
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    const storedData = otpStore.get(`reset_${email}`);
    
    if (!storedData) {
      return res.status(400).json({ error: 'Reset link expired or not found.' });
    }

    // Check if token is expired
    if (new Date() > storedData.expiry) {
      otpStore.delete(`reset_${email}`);
      return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });
    }

    // Verify token
    if (storedData.token !== token) {
      return res.status(400).json({ error: 'Invalid reset link.' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password
    await pool.execute('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, storedData.userId]);

    // Clear reset token
    otpStore.delete(`reset_${email}`);

    res.status(200).json({ 
      message: 'Password reset successfully'
    });

  } catch (err) {
    console.error('Password reset error:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// CRON JOBS
// CRON JOB: Deactivate subscription after trial
cron.schedule('0 0 * * *', async () => {
  // Runs every day at midnight
  const now = new Date();
  console.log('Running subscription deactivation cron job at:', now);
  
  try {
    // Update Configuration model subscriptions
    const [result] = await pool.execute(
      'UPDATE configurations SET subscription = ? WHERE trial_ends_at <= ? AND subscription = ?', 
      ['inactive', now, 'active']
    );
    
    console.log(`Deactivated ${result.affectedRows} expired subscriptions`);
  } catch (error) {
    console.error('Error in subscription deactivation cron job:', error);
  }
});

// Manual API to deactivate expired subscriptions
app.post('/api/deactivate-expired-subscriptions', auth, async (req, res) => {
  try {
    const [currentUsers] = await pool.execute('SELECT role FROM users WHERE id = ?', [req.userId]);
    if (currentUsers.length === 0 || currentUsers[0].role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can perform this action.' });
    }

    const now = new Date();
    const [result] = await pool.execute(
      'UPDATE configurations SET subscription = ? WHERE trial_ends_at <= ? AND subscription = ?', 
      ['inactive', now, 'active']
    );

    res.status(200).json({ 
      message: `Deactivated ${result.affectedRows} expired subscriptions`,
      deactivatedCount: result.affectedRows,
      currentTime: now
    });
  } catch (err) {
    console.error('Error deactivating expired subscriptions:', err);
    res.status(500).json({ error: 'Failed to deactivate expired subscriptions', details: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('MySQL database connected successfully');
}); 