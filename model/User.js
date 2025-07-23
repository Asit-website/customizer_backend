const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: {
    type: String
  },
  email: {
    type: String,
    unique: true
  },
  password: {
    type: String
  },
  phone: {
    type: String
  },
  role: {
    type: String,
    enum: ['superadmin', 'user'],
    default: 'user'
  },
  active: {
    type: Boolean,
    default: true
  }
});

module.exports = mongoose.model('User', userSchema); 