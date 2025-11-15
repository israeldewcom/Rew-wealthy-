// routes/upload.js
const express = require('express');
const { auth } = require('../middleware/auth');
const upload = require('../middleware/upload');
const cloudinary = require('../utils/cloudinary');

const router = express.Router();

router.use(auth);

router.post('/', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: 'raw-wealthy',
      resource_type: 'auto'
    });

    res.status(200).json({
      success: true,
      data: {
        url: result.secure_url,
        public_id: result.public_id,
        format: result.format,
        bytes: result.bytes
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'File upload failed',
      error: error.message
    });
  }
});

module.exports = router;
