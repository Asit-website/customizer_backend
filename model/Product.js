const mongoose = require('mongoose');

const ProductDetailsSchema = new mongoose.Schema({
  id: Number,
  image: String,
  description: String,
  size: String,
  color: String,
  width: Number,
  textTopRatio: Number
}, { _id: false });

const CanvasObjectSchema = new mongoose.Schema({
  type: String,
  left: Number,
  top: Number,
  scaleX: Number,
  scaleY: Number,
  angle: Number,
  opacity: Number,
  flipX: Boolean,
  flipY: Boolean,
  originX: String,
  originY: String,
  selectable: Boolean,
  evented: Boolean,
  visible: Boolean,
  src: String,
  isTshirtBase: Boolean,
  isIcon: Boolean,
  hasControls: Boolean,
  hasBorders: Boolean,
  lockMovementX: Boolean,
  lockMovementY: Boolean,
  lockScalingX: Boolean,
  lockScalingY: Boolean,
  lockRotation: Boolean,
  name: String,
  text: String,
  fontSize: Number,
  fontFamily: String,
  fontStyle: String,
  fontWeight: String,
  fill: String,
  textAlign: String,
  charSpacing: Number,
  lineHeight: Number,
  isEmoji: Boolean,
  editable: Boolean
}, { _id: false });

const CanvasSchema = new mongoose.Schema({
  width: Number,
  height: Number,
  objects: [CanvasObjectSchema],
  backgroundColor: String
}, { _id: false });

const DesignSchema = new mongoose.Schema({
  appliedDesigns: [CanvasObjectSchema],
  appliedPatterns: [mongoose.Schema.Types.Mixed],
  customUploads: [mongoose.Schema.Types.Mixed]
}, { _id: false });

const TextSchema = new mongoose.Schema({
  textObjects: [CanvasObjectSchema],
  currentTextColor: String,
  currentFontFamily: String,
  currentFontStyle: String,
  currentTextSize: Number,
  currentTextSpacing: Number,
  currentTextArc: Number,
  textFlipX: Boolean,
  textFlipY: Boolean
}, { _id: false });

const ClipartSchema = new mongoose.Schema({
  emojis: [mongoose.Schema.Types.Mixed],
  icons: [mongoose.Schema.Types.Mixed],
  customIcons: [mongoose.Schema.Types.Mixed]
}, { _id: false });

const PatternSchema = new mongoose.Schema({
  appliedPattern: mongoose.Schema.Types.Mixed
}, { _id: false });

const ImageSettingsSchema = new mongoose.Schema({
  flipX: Boolean,
  flipY: Boolean,
  selectedColor: {
    color: String,
    name: String
  },
  opacity: Number,
  rotation: Number
}, { _id: false });

const UiStateSchema = new mongoose.Schema({
  showSidebar: Boolean,
  clippingPath: mongoose.Schema.Types.Mixed,
  customTextState: {
    text: String,
    showEditModal: Boolean,
    showAddModal: Boolean
  }
}, { _id: false });

const MetadataSchema = new mongoose.Schema({
  canvasObjectCount: Number,
  hasText: Boolean,
  hasDesign: Boolean,
  hasCustomUpload: Boolean
}, { _id: false });

const Model3DSchema = new mongoose.Schema({
  url: String,
  generatedAt: String,
  format: String,
  screenshotUrl: String
}, { _id: false });

const ProductSchema = new mongoose.Schema({
  id: Number,
  timestamp: String,
  product: ProductDetailsSchema,
  canvas: CanvasSchema,
  design: DesignSchema,
  text: TextSchema,
  clipart: ClipartSchema,
  pattern: PatternSchema,
  imageSettings: ImageSettingsSchema,
  uiState: UiStateSchema,
  metadata: MetadataSchema,
  screenshot: String,
  model3D: Model3DSchema
});

module.exports = mongoose.model('Product', ProductSchema); 