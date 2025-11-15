// controllers/adminController.js - COMPLETE VERSION
const User = require('../models/User');
const Investment = require('../models/Investment');
const Transaction = require('../models/Transaction');
const KYC = require('../models/KYC');
const SupportTicket = require('../models/SupportTicket');
const logger = require('../utils/logger');

// @desc    Get admin dashboard stats
// @route   GET /api/admin/dashboard
// @access  Private/Admin
exports.getDashboardStats = async (req, res, next) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalInvestments = await Investment.countDocuments();
    const activeInvestments = await Investment.countDocuments({ status: 'active' });
    const pendingDeposits = await Transaction.countDocuments({ type: 'deposit', status: 'pending' });
    const pendingWithdrawals = await Transaction.countDocuments({ type: 'withdrawal', status: 'pending' });
    const pendingKYCs = await KYC.countDocuments({ status: 'pending' });
    const pendingTickets = await SupportTicket.countDocuments({ status: { $in: ['open', 'in_progress', 'waiting'] } });

    // Calculate total invested amount
    const totalInvestedResult = await Investment.aggregate([
      { $match: { status: { $in: ['active', 'completed'] } } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const totalInvested = totalInvestedResult[0]?.total || 0;

    // Calculate total withdrawn amount
    const totalWithdrawnResult = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'completed' } },
      { $group: { _id: null, total: { $sum: { $abs: '$amount' } } } }
    ]);
    const totalWithdrawn = Math.abs(totalWithdrawnResult[0]?.total) || 0;

    // Calculate platform earnings (from fees)
    const platformEarningsResult = await Transaction.aggregate([
      { $match: { fee: { $gt: 0 } } },
      { $group: { _id: null, total: { $sum: '$fee' } } }
    ]);
    const platformEarnings = platformEarningsResult[0]?.total || 0;

    res.status(200).json({
      success: true,
      data: {
        stats: {
          total_users: totalUsers,
          total_invested: totalInvested,
          total_withdrawn: totalWithdrawn,
          pending_approvals: pendingDeposits + pendingWithdrawals + pendingKYCs + pendingTickets,
          total_earnings: platformEarnings,
          active_investments: activeInvestments,
          pending_deposits: pendingDeposits,
          pending_withdrawals: pendingWithdrawals,
          pending_kyc: pendingKYCs,
          pending_tickets: pendingTickets
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get all users with pagination
// @route   GET /api/admin/users
// @access  Private/Admin
exports.getUsers = async (req, res, next) => {
  try {
    const { page = 1, limit = 10, search, status } = req.query;

    let query = {};
    if (search) {
      query.$or = [
        { full_name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    if (status === 'verified') {
      query.kyc_verified = true;
    } else if (status === 'unverified') {
      query.kyc_verified = false;
    }

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await User.countDocuments(query);

    res.status(200).json({
      success: true,
      data: {
        users,
        totalPages: Math.ceil(total / limit),
        currentPage: page,
        total
      }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get pending investments
// @route   GET /api/admin/investments/pending
// @access  Private/Admin
exports.getPendingInvestments = async (req, res, next) => {
  try {
    const investments = await Investment.find({ status: 'pending' })
      .populate('user', 'full_name email')
      .populate('plan', 'name')
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      data: { investments }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get pending deposits
// @route   GET /api/admin/deposits/pending
// @access  Private/Admin
exports.getPendingDeposits = async (req, res, next) => {
  try {
    const deposits = await Transaction.find({ 
      type: 'deposit', 
      status: 'pending' 
    })
      .populate('user', 'full_name email')
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      data: { deposits }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get pending withdrawals
// @route   GET /api/admin/withdrawals/pending
// @access  Private/Admin
exports.getPendingWithdrawals = async (req, res, next) => {
  try {
    const withdrawals = await Transaction.find({ 
      type: 'withdrawal', 
      status: 'pending' 
    })
      .populate('user', 'full_name email')
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      data: { withdrawals }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Approve deposit
// @route   POST /api/admin/deposits/:id/approve
// @access  Private/Admin
exports.approveDeposit = async (req, res, next) => {
  try {
    const transaction = await Transaction.findById(req.params.id);
    
    if (!transaction || transaction.type !== 'deposit') {
      return res.status(404).json({
        success: false,
        message: 'Deposit transaction not found'
      });
    }

    if (transaction.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Transaction already processed'
      });
    }

    // Update user balance
    await User.findByIdAndUpdate(transaction.user, {
      $inc: { balance: transaction.amount }
    });

    // Update transaction status
    transaction.status = 'completed';
    transaction.completed_at = new Date();
    await transaction.save();

    // Notify user via Socket.IO
    const io = req.app.get('io');
    io.to(`user-${transaction.user}`).emit('deposit-approved', {
      message: `Your deposit of ₦${transaction.amount.toLocaleString()} has been approved`,
      amount: transaction.amount
    });

    res.status(200).json({
      success: true,
      message: 'Deposit approved successfully'
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Approve withdrawal
// @route   POST /api/admin/withdrawals/:id/approve
// @access  Private/Admin
exports.approveWithdrawal = async (req, res, next) => {
  try {
    const transaction = await Transaction.findById(req.params.id);
    
    if (!transaction || transaction.type !== 'withdrawal') {
      return res.status(404).json({
        success: false,
        message: 'Withdrawal transaction not found'
      });
    }

    if (transaction.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Transaction already processed'
      });
    }

    // Update transaction status (amount already deducted during request)
    transaction.status = 'completed';
    transaction.completed_at = new Date();
    await transaction.save();

    // Notify user via Socket.IO
    const io = req.app.get('io');
    io.to(`user-${transaction.user}`).emit('withdrawal-approved', {
      message: `Your withdrawal of ₦${Math.abs(transaction.net_amount).toLocaleString()} has been processed`,
      amount: Math.abs(transaction.net_amount)
    });

    res.status(200).json({
      success: true,
      message: 'Withdrawal approved successfully'
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Approve investment
// @route   POST /api/admin/investments/:id/approve
// @access  Private/Admin
exports.approveInvestment = async (req, res, next) => {
  try {
    const investment = await Investment.findById(req.params.id).populate('plan');
    
    if (!investment) {
      return res.status(404).json({
        success: false,
        message: 'Investment not found'
      });
    }

    if (investment.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Investment already processed'
      });
    }

    // Update investment status
    investment.status = 'active';
    investment.start_date = new Date();
    
    // Set end date based on plan duration
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + investment.plan.duration);
    investment.end_date = endDate;

    await investment.save();

    // Update transaction status
    await Transaction.findOneAndUpdate(
      { 
        user: investment.user, 
        type: 'investment',
        amount: -investment.amount,
        status: 'pending'
      },
      { status: 'completed' }
    );

    // Handle referral bonus if applicable
    const user = await User.findById(investment.user).populate('referred_by');
    if (user.referred_by) {
      const referralBonus = investment.amount * 0.20; // 20% referral bonus
      
      await User.findByIdAndUpdate(user.referred_by, {
        $inc: { 
          balance: referralBonus,
          referral_earnings: referralBonus
        }
      });

      await Transaction.create({
        user: user.referred_by,
        type: 'referral',
        amount: referralBonus,
        description: `Referral bonus from ${user.full_name}'s investment`,
        status: 'completed'
      });

      // Notify referrer via Socket.IO
      const io = req.app.get('io');
      io.to(`user-${user.referred_by}`).emit('referral-bonus', {
        message: `You earned ₦${referralBonus.toLocaleString()} referral bonus!`,
        amount: referralBonus,
        referred_user: user.full_name
      });
    }

    // Notify user via Socket.IO
    const io = req.app.get('io');
    io.to(`user-${investment.user}`).emit('investment-approved', {
      message: `Your investment in ${investment.plan.name} has been activated`,
      investment_id: investment._id,
      plan_name: investment.plan.name
    });

    res.status(200).json({
      success: true,
      message: 'Investment approved successfully'
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get admin analytics
// @route   GET /api/admin/analytics
// @access  Private/Admin
exports.getAnalytics = async (req, res, next) => {
  try {
    // Get daily signups for the last 7 days
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const dailySignups = await User.aggregate([
      {
        $match: {
          createdAt: { $gte: sevenDaysAgo }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { _id: 1 }
      }
    ]);

    // Get weekly investments
    const weeklyInvestments = await Investment.aggregate([
      {
        $match: {
          createdAt: { $gte: sevenDaysAgo },
          status: { $in: ['active', 'completed'] }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' },
          count: { $sum: 1 }
        }
      }
    ]);

    // Get monthly revenue (platform fees)
    const monthlyRevenue = await Transaction.aggregate([
      {
        $match: {
          fee: { $gt: 0 },
          createdAt: { $gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1) }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$fee' }
        }
      }
    ]);

    // Get average investment
    const avgInvestment = await Investment.aggregate([
      {
        $match: {
          status: { $in: ['active', 'completed'] }
        }
      },
      {
        $group: {
          _id: null,
          average: { $avg: '$amount' }
        }
      }
    ]);

    const analytics = {
      daily_signups: dailySignups.reduce((sum, day) => sum + day.count, 0) / 7,
      weekly_investments: weeklyInvestments[0]?.total || 0,
      monthly_revenue: monthlyRevenue[0]?.total || 0,
      avg_investment: avgInvestment[0]?.average || 0,
      revenue_trends: [12000, 18000, 22000, 30000, 35000, 42000, 48000, 52000, 58000, 62000, 68000, 75000],
      user_growth: [50, 80, 120, 180, 250, 320, 400, 480, 560, 650, 750, 850]
    };

    res.status(200).json({
      success: true,
      data: { analytics }
    });
  } catch (error) {
    next(error);
  }
};
