// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  full_name: {
    type: String,
    required: [true, 'Full name is required'],
    trim: true,
    maxlength: [100, 'Full name cannot exceed 100 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: {
      validator: function(email) {
        return /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(email);
      },
      message: 'Please enter a valid email'
    }
  },
  phone: {
    type: String,
    required: [true, 'Phone number is required'],
    validate: {
      validator: function(phone) {
        return /^\+?[\d\s-()]{10,}$/.test(phone);
      },
      message: 'Please enter a valid phone number'
    }
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  },
  balance: {
    type: Number,
    default: 0,
    min: [0, 'Balance cannot be negative']
  },
  total_earnings: {
    type: Number,
    default: 0
  },
  referral_earnings: {
    type: Number,
    default: 0
  },
  referral_code: {
    type: String,
    unique: true,
    sparse: true
  },
  referred_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  risk_tolerance: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  investment_strategy: {
    type: String,
    enum: ['conservative', 'balanced', 'aggressive'],
    default: 'balanced'
  },
  kyc_verified: {
    type: Boolean,
    default: false
  },
  kyc_status: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'not_submitted'],
    default: 'not_submitted'
  },
  two_factor_enabled: {
    type: Boolean,
    default: false
  },
  two_factor_secret: {
    type: String,
    select: false
  },
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    bank_code: String,
    is_verified: { type: Boolean, default: false }
  },
  profile_image: String,
  email_verified: {
    type: Boolean,
    default: false
  },
  phone_verified: {
    type: Boolean,
    default: false
  },
  last_login: Date,
  login_history: [{
    ip: String,
    user_agent: String,
    timestamp: { type: Date, default: Date.now }
  }],
  preferences: {
    email_notifications: { type: Boolean, default: true },
    sms_notifications: { type: Boolean, default: false },
    push_notifications: { type: Boolean, default: true },
    currency: { type: String, default: 'NGN' },
    language: { type: String, default: 'en' },
    timezone: { type: String, default: 'Africa/Lagos' }
  },
  security_questions: [{
    question: String,
    answer: { type: String, select: false }
  }],
  is_active: {
    type: Boolean,
    default: true
  },
  deactivation_reason: String,
  deleted_at: Date
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for referral count
userSchema.virtual('referral_count', {
  ref: 'User',
  localField: '_id',
  foreignField: 'referred_by',
  count: true
});

// Virtual for active referrals
userSchema.virtual('active_referrals', {
  ref: 'User',
  localField: '_id',
  foreignField: 'referred_by',
  match: { is_active: true }
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ referral_code: 1 });
userSchema.index({ 'bank_details.account_number': 1 });
userSchema.index({ created_at: -1 });

// Pre-save middleware
userSchema.pre('save', function(next) {
  if (!this.referral_code) {
    this.referral_code = this.generateReferralCode();
  }
  next();
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Instance methods
userSchema.methods.generateReferralCode = function() {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
};

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.isActive = function() {
  return this.is_active && !this.deleted_at;
};

userSchema.methods.getDashboardStats = async function() {
  const Investment = mongoose.model('Investment');
  const Transaction = mongoose.model('Transaction');
  
  const activeInvestments = await Investment.countDocuments({ 
    user: this._id, 
    status: 'active' 
  });
  
  const totalDeposits = await Transaction.aggregate([
    { $match: { user: this._id, type: 'deposit', status: 'completed' } },
    { $group: { _id: null, total: { $sum: '$amount' } } }
  ]);
  
  const totalWithdrawals = await Transaction.aggregate([
    { $match: { user: this._id, type: 'withdrawal', status: 'completed' } },
    { $group: { _id: null, total: { $sum: { $abs: '$amount' } } } }
  ]);

  return {
    active_investments: activeInvestments,
    total_deposits: totalDeposits[0]?.total || 0,
    total_withdrawals: totalWithdrawals[0]?.total || 0
  };
};

module.exports = mongoose.model('User', userSchema);
