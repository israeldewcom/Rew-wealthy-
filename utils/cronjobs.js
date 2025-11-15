// utils/cronJobs.js
const cron = require('node-cron');
const Investment = require('../models/Investment');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const logger = require('./logger');

// Run daily at midnight to calculate earnings
cron.schedule('0 0 * * *', async () => {
  try {
    logger.info('Starting daily earnings calculation...');
    
    const activeInvestments = await Investment.find({ 
      status: 'active',
      end_date: { $gt: new Date() },
      next_profit_date: { $lte: new Date() }
    }).populate('user plan');

    let processedCount = 0;
    let totalEarnings = 0;

    for (let investment of activeInvestments) {
      try {
        const dailyEarning = investment.calculateDailyEarning();
        
        await investment.addProfit(dailyEarning);
        
        // Update user balance
        await User.findByIdAndUpdate(investment.user._id, {
          $inc: { 
            balance: dailyEarning,
            total_earnings: dailyEarning
          }
        });

        // Create earning transaction
        await Transaction.create({
          user: investment.user._id,
          type: 'earning',
          amount: dailyEarning,
          description: `Daily earnings from ${investment.plan.name}`,
          status: 'completed',
          metadata: {
            investment_id: investment._id,
            plan_name: investment.plan.name
          }
        });

        processedCount++;
        totalEarnings += dailyEarning;

        logger.info(`Earnings calculated for investment ${investment._id}: ₦${dailyEarning}`);
      } catch (investmentError) {
        logger.error(`Error processing investment ${investment._id}:`, investmentError);
      }
    }

    logger.info(`Daily earnings calculation completed. Processed ${processedCount} investments, Total: ₦${totalEarnings}`);
  } catch (error) {
    logger.error('Error in daily earnings cron job:', error);
  }
});

// Check and complete expired investments daily at 1 AM
cron.schedule('0 1 * * *', async () => {
  try {
    logger.info('Checking expired investments...');
    
    const expiredInvestments = await Investment.find({ 
      status: 'active',
      end_date: { $lte: new Date() }
    }).populate('user plan');

    let completedCount = 0;
    let renewedCount = 0;

    for (let investment of expiredInvestments) {
      try {
        if (investment.auto_renew && investment.user.balance >= investment.amount) {
          // Auto-renew investment
          const newInvestment = await Investment.create({
            user: investment.user._id,
            plan: investment.plan._id,
            amount: investment.amount,
            auto_renew: true,
            status: 'pending',
            renewed_from: investment._id,
            renewal_count: investment.renewal_count + 1
          });

          // Create transaction for auto-renewal
          await Transaction.create({
            user: investment.user._id,
            type: 'investment',
            amount: -investment.amount,
            description: `Auto-renew investment in ${investment.plan.name}`,
            status: 'pending',
            metadata: {
              investment_id: newInvestment._id,
              renewed_from: investment._id
            }
          });

          renewedCount++;
          logger.info(`Investment ${investment._id} auto-renewed as ${newInvestment._id}`);
        }

        // Mark original investment as completed
        investment.status = 'completed';
        await investment.save();

        completedCount++;
        logger.info(`Investment ${investment._id} marked as completed`);
      } catch (investmentError) {
        logger.error(`Error processing expired investment ${investment._id}:`, investmentError);
      }
    }

    logger.info(`Expired investments processed. Completed: ${completedCount}, Renewed: ${renewedCount}`);
  } catch (error) {
    logger.error('Error in expired investments cron job:', error);
  }
});

// Weekly report every Monday at 6 AM
cron.schedule('0 6 * * 1', async () => {
  try {
    logger.info('Generating weekly report...');
    
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);

    // Get weekly stats
    const newUsers = await User.countDocuments({ 
      createdAt: { $gte: weekAgo } 
    });

    const weeklyInvestments = await Investment.aggregate([
      {
        $match: { 
          createdAt: { $gte: weekAgo },
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

    const weeklyEarnings = await Transaction.aggregate([
      {
        $match: { 
          createdAt: { $gte: weekAgo },
          type: 'earning',
          status: 'completed'
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);

    const report = {
      period: 'weekly',
      start_date: weekAgo,
      end_date: new Date(),
      new_users: newUsers,
      total_investments: weeklyInvestments[0]?.total || 0,
      investment_count: weeklyInvestments[0]?.count || 0,
      total_earnings: weeklyEarnings[0]?.total || 0
    };

    logger.info('Weekly report generated:', report);
    
    // Here you could send this report to admin email
    // or store it in a reports collection

  } catch (error) {
    logger.error('Error in weekly report cron job:', error);
  }
});

// Database backup reminder (first day of every month)
cron.schedule('0 2 1 * *', () => {
  logger.info('REMINDER: Monthly database backup should be performed');
  // In production, you would trigger an actual backup process here
});

module.exports = cron;
