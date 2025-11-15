// models/Investment.js
const mongoose = require('mongoose');

const investmentSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  plan: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'InvestmentPlan',
    required: true
  },
  amount: {
    type: Number,
    required: [true, 'Investment amount is required'],
    min: [0, 'Amount cannot be negative']
  },
  current_balance: {
    type: Number,
    default: 0
  },
  total_earned: {
    type: Number,
    default: 0
  },
  daily_earnings: {
    type: Number,
    default: 0
  },
  start_date: {
    type: Date,
    default: Date.now
  },
  end_date: {
    type: Date,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'active', 'completed', 'cancelled', 'suspended'],
    default: 'pending'
  },
  auto_renew: {
    type: Boolean,
    default: false
  },
  last_profit_date: Date,
  next_profit_date: Date,
  profit_history: [{
    date: Date,
    amount: Number,
    balance_before: Number,
    balance_after: Number
  }],
  payment_proof: {
    image_url: String,
    uploaded_at: Date,
    verified: { type: Boolean, default: false }
  },
  admin_notes: String,
  cancellation_reason: String,
  renewed_from: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Investment'
  },
  renewal_count: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for days remaining
investmentSchema.virtual('days_remaining').get(function() {
  if (this.status !== 'active') return 0;
  const now = new Date();
  const end = new Date(this.end_date);
  const diffTime = end - now;
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
});

// Virtual for total days
investmentSchema.virtual('total_days').get(function() {
  const start = new Date(this.start_date);
  const end = new Date(this.end_date);
  const diffTime = end - start;
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
});

// Virtual for progress percentage
investmentSchema.virtual('progress_percentage').get(function() {
  if (this.status !== 'active') return 100;
  const total = this.total_days;
  const remaining = this.days_remaining;
  return Math.round(((total - remaining) / total) * 100);
});

// Indexes
investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ status: 1, start_date: 1 });
investmentSchema.index({ end_date: 1 });

// Pre-save middleware
investmentSchema.pre('save', function(next) {
  if (this.isModified('amount') || this.isNew) {
    if (this.populated('plan')) {
      const endDate = new Date(this.start_date);
      endDate.setDate(endDate.getDate() + this.plan.duration);
      this.end_date = endDate;
      
      // Set next profit date to tomorrow
      const nextProfit = new Date();
      nextProfit.setDate(nextProfit.getDate() + 1);
      nextProfit.setHours(0, 0, 0, 0);
      this.next_profit_date = nextProfit;
    }
  }
  next();
});

// Static methods
investmentSchema.statics.getActiveInvestments = function() {
  return this.find({ 
    status: 'active',
    end_date: { $gt: new Date() }
  }).populate('user plan');
};

investmentSchema.statics.getPendingInvestments = function() {
  return this.find({ status: 'pending' })
    .populate('user plan')
    .sort({ createdAt: -1 });
};

// Instance methods
investmentSchema.methods.calculateDailyEarning = function() {
  if (!this.populated('plan')) return 0;
  return this.amount * (this.plan.daily_interest / 100);
};

investmentSchema.methods.canWithdraw = function() {
  return this.status === 'active' && this.current_balance > 0;
};

investmentSchema.methods.addProfit = async function(amount) {
  this.current_balance += amount;
  this.total_earned += amount;
  this.daily_earnings = amount;
  this.last_profit_date = new Date();
  
  // Set next profit date
  const nextProfit = new Date();
  nextProfit.setDate(nextProfit.getDate() + 1);
  nextProfit.setHours(0, 0, 0, 0);
  this.next_profit_date = nextProfit;
  
  // Add to profit history
  this.profit_history.push({
    date: new Date(),
    amount: amount,
    balance_before: this.current_balance - amount,
    balance_after: this.current_balance
  });
  
  // Keep only last 30 days of profit history
  if (this.profit_history.length > 30) {
    this.profit_history = this.profit_history.slice(-30);
  }
  
  await this.save();
};

module.exports = mongoose.model('Investment', investmentSchema);
