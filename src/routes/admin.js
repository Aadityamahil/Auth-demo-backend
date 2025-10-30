const express = require('express');
const User = require('../models/User');

const router = express.Router();

// Simple API key check
router.use((req, res, next) => {
  const key = req.headers['x-admin-key'];
  if (!key || key !== (process.env.ADMIN_API_KEY || 'admin_dev_key')) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  next();
});

router.post('/reset-device/:email', async (req, res) => {
  const { email } = req.params;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: 'User not found' });
  user.registeredDeviceIdHash = null;
  user.registeredAt = null;
  await user.save();
  return res.json({ message: 'Device registration cleared', email });
});

module.exports = router;


