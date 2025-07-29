const mongoose = require('mongoose');

const CustomizableDataSchema = new mongoose.Schema({
  title: String,
  shortDescription: String,
  files: [String], // URLs or file paths
}, { _id: false });

const LayerDesignSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  sq: { type: String, required: true }, // BigCommerce SQ
  designName: { type: String, required: true },
  layersDesign: { type: Object, required: true },
  customizableData: [CustomizableDataSchema],
}, { timestamps: true });

module.exports = mongoose.model('LayerDesign', LayerDesignSchema); 