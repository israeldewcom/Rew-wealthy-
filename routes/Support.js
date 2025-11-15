// routes/support.js
const express = require('express');
const {
  createTicket,
  getUserTickets,
  getTicket,
  addReply,
  getFAQs
} = require('../controllers/supportController');
const { auth } = require('../middleware/auth');

const router = express.Router();

router.get('/faqs', getFAQs);

router.use(auth);

router.post('/tickets', createTicket);
router.get('/tickets', getUserTickets);
router.get('/tickets/:id', getTicket);
router.post('/tickets/:id/reply', addReply);

module.exports = router;
