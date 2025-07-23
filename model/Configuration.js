const mongoose = require('mongoose');

const configurationSchema = new mongoose.Schema({
  storeId: {
    type: String
  },
  storeUrl: {
    type: String
  },
  storeAccessToken: {
    type: String
  },
  storeEndpoint: {
    type: String
  },
  subscription: {
    type: String,
    enum: ['active', 'inactive']
  },
  trialEndsAt: {
    type: Date
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, { timestamps: true });

module.exports = mongoose.model('Configuration', configurationSchema); 