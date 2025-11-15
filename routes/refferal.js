// routes/referrals.js
const express = require('express');
const {
  getReferralStats,
  getReferralLink,
  getReferredUsers,
  getReferralEarnings,
  processReferralBonus
} = require('../controllers/referralController');
const { auth, adminAuth } = require('../middleware/auth');

const router = express.Router();

router.use(auth);

router.get('/stats', getReferralStats);
router.get('/link', getReferralLink);
router.get('/users', getReferredUsers);
router.get('/earnings', getReferralEarnings);

// Admin only route for processing bonuses
router.post('/process-bonus', adminAuth, processReferralBonus);

module.exports = router;
