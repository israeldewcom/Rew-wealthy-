// controllers/kycController.js
const KYC = require('../models/KYC');
const User = require('../models/User');
const { sendEmail } = require('../utils/emailService');
const logger = require('../utils/logger');

// @desc    Submit KYC application
// @route   POST /api/kyc
// @access  Private
exports.submitKYC = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { id_type, id_number } = req.body;

    // Check if user already has a KYC submission
    const existingKYC = await KYC.findOne({ user: userId });
    if (existingKYC && existingKYC.status === 'pending') {
      return res.status(400).json({
        success: false,
        message: 'You already have a pending KYC application'
      });
    }

    // Validate file uploads
    if (!req.files || !req.files.id_front || !req.files.id_back || !req.files.selfie_with_id) {
      return res.status(400).json({
        success: false,
        message: 'Please upload all required documents: ID front, ID back, and selfie with ID'
      });
    }

    // Create KYC application
    const kyc = await KYC.create({
      user: userId,
      id_type,
      id_number,
      id_front_image: req.files.id_front[0].path,
      id_back_image: req.files.id_back[0].path,
      selfie_with_id: req.files.selfie_with_id[0].path,
      status: 'pending'
    });

    // Update user KYC status
    await User.findByIdAndUpdate(userId, {
      kyc_status: 'pending'
    });

    // Notify admin via Socket.IO
    const io = req.app.get('io');
    io.to('admin-room').emit('new-kyc', {
      message: 'New KYC application submitted',
      kycId: kyc._id,
      userId: userId,
      userName: req.user.full_name
    });

    // Send confirmation email to user
    await sendEmail({
      to: req.user.email,
      subject: 'KYC Application Received - Raw Wealthy',
      template: 'kyc_submitted',
      context: {
        name: req.user.full_name,
        kycId: kyc._id
      }
    });

    logger.info(`KYC application submitted by user ${userId}`);

    res.status(201).json({
      success: true,
      message: 'KYC application submitted successfully',
      data: { kyc }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get KYC status
// @route   GET /api/kyc
// @access  Private
exports.getKYCStatus = async (req, res, next) => {
  try {
    const kyc = await KYC.findOne({ user: req.user.id })
      .populate('reviewed_by', 'full_name email');

    if (!kyc) {
      return res.status(200).json({
        success: true,
        data: { 
          kyc: null,
          status: 'not_submitted'
        }
      });
    }

    res.status(200).json({
      success: true,
      data: { kyc }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get all KYC applications (Admin)
// @route   GET /api/admin/kyc
// @access  Private/Admin
exports.getKYCApplications = async (req, res, next) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    
    const query = {};
    if (status) query.status = status;

    const kycs = await KYC.find(query)
      .populate('user', 'full_name email phone')
      .populate('reviewed_by', 'full_name')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await KYC.countDocuments(query);

    res.status(200).json({
      success: true,
      data: {
        kycs,
        totalPages: Math.ceil(total / limit),
        currentPage: page,
        total
      }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Approve KYC application (Admin)
// @route   PUT /api/admin/kyc/:id/approve
// @access  Private/Admin
exports.approveKYC = async (req, res, next) => {
  try {
    const kyc = await KYC.findById(req.params.id).populate('user');
    
    if (!kyc) {
      return res.status(404).json({
        success: false,
        message: 'KYC application not found'
      });
    }

    if (kyc.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'KYC application already processed'
      });
    }

    // Update KYC status
    kyc.status = 'approved';
    kyc.reviewed_by = req.user.id;
    kyc.reviewed_at = new Date();
    await kyc.save();

    // Update user KYC status
    await User.findByIdAndUpdate(kyc.user._id, {
      kyc_verified: true,
      kyc_status: 'approved'
    });

    // Notify user via Socket.IO
    const io = req.app.get('io');
    io.to(`user-${kyc.user._id}`).emit('kyc-approved', {
      message: 'Your KYC application has been approved',
      kycId: kyc._id
    });

    // Send approval email
    await sendEmail({
      to: kyc.user.email,
      subject: 'KYC Application Approved - Raw Wealthy',
      template: 'kyc_approved',
      context: {
        name: kyc.user.full_name
      }
    });

    logger.info(`KYC application ${kyc._id} approved by admin ${req.user.id}`);

    res.status(200).json({
      success: true,
      message: 'KYC application approved successfully'
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Reject KYC application (Admin)
// @route   PUT /api/admin/kyc/:id/reject
// @access  Private/Admin
exports.rejectKYC = async (req, res, next) => {
  try {
    const { rejection_reason } = req.body;
    
    if (!rejection_reason) {
      return res.status(400).json({
        success: false,
        message: 'Rejection reason is required'
      });
    }

    const kyc = await KYC.findById(req.params.id).populate('user');
    
    if (!kyc) {
      return res.status(404).json({
        success: false,
        message: 'KYC application not found'
      });
    }

    if (kyc.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'KYC application already processed'
      });
    }

    // Update KYC status
    kyc.status = 'rejected';
    kyc.reviewed_by = req.user.id;
    kyc.reviewed_at = new Date();
    kyc.rejection_reason = rejection_reason;
    await kyc.save();

    // Update user KYC status
    await User.findByIdAndUpdate(kyc.user._id, {
      kyc_verified: false,
      kyc_status: 'rejected'
    });

    // Notify user via Socket.IO
    const io = req.app.get('io');
    io.to(`user-${kyc.user._id}`).emit('kyc-rejected', {
      message: 'Your KYC application has been rejected',
      kycId: kyc._id,
      reason: rejection_reason
    });

    // Send rejection email
    await sendEmail({
      to: kyc.user.email,
      subject: 'KYC Application Update - Raw Wealthy',
      template: 'kyc_rejected',
      context: {
        name: kyc.user.full_name,
        reason: rejection_reason
      }
    });

    logger.info(`KYC application ${kyc._id} rejected by admin ${req.user.id}`);

    res.status(200).json({
      success: true,
      message: 'KYC application rejected successfully'
    });
  } catch (error) {
    next(error);
  }
};
