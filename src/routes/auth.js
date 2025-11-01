const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { sha256Hex } = require('../utils/hashDevice');
const authMiddleware = require('../middleware/auth');

const router = express.Router();

// Register (for local demo convenience)
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });
    
    // Get FingerprintJS visitorId for device binding (browser-specific, which is fine for password login)
    const fpVisitorId = req.headers['x-fp-visitor-id'] || req.body.fpVisitorId || req.body.deviceIdRaw;
    
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ message: 'User already exists' });
    
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Create user with device ID if provided
    const userData = { email, passwordHash };
    if (fpVisitorId) {
      const deviceHash = sha256Hex(fpVisitorId);
      userData.registeredDeviceIdHash = deviceHash;
      userData.registeredAt = new Date();
      console.log('[AUTH] Register - Device ID stored:', {
        email,
        deviceHash,
        hasVisitorId: !!fpVisitorId,
      });
    } else {
      console.warn('[AUTH] Register - No device fingerprint provided');
    }
    
    const user = await User.create(userData);
    return res.status(201).json({ 
      message: 'Registered', 
      email: user.email,
      deviceIdHash: user.registeredDeviceIdHash,
    });
  } catch (err) {
    console.error('[AUTH] Registration error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Login with device check (binds to FingerprintJS visitorId if provided)
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    // Prefer FingerprintJS visitorId from header or body; fall back to legacy deviceIdRaw
    const fpVisitorId = req.headers['x-fp-visitor-id'] || req.body.fpVisitorId || req.body.deviceIdRaw;
    if (!email || !password || !fpVisitorId) {
      return res.status(400).json({ message: 'Missing email/password/fingerprint' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    const incomingDeviceHash = sha256Hex(fpVisitorId);
    // Debug log for troubleshooting device binding
    console.log('[AUTH] Login attempt', {
      email,
      hasStoredDevice: Boolean(user.registeredDeviceIdHash),
      storedDeviceHash: user.registeredDeviceIdHash || null,
      incomingDeviceHash,
    });

    if (!user.registeredDeviceIdHash) {
      user.registeredDeviceIdHash = incomingDeviceHash;
      user.registeredAt = new Date();
      await user.save();
    } else if (user.registeredDeviceIdHash !== incomingDeviceHash) {
      console.warn('[AUTH] Device mismatch — denying login', {
        email,
        storedDeviceHash: user.registeredDeviceIdHash,
        incomingDeviceHash,
      });
      return res.status(403).json({ message: '❌ Access Denied — This account is already linked to another device.' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'dev_secret',
      { expiresIn: '15m' }
    );

    const isProd = process.env.NODE_ENV === 'production'
    res.cookie('token', token, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'strict',
      maxAge: 15 * 60 * 1000,
    });

    return res.json({
      message: 'Logged in',
      deviceIdHash: user.registeredDeviceIdHash,
      email: user.email,
    });
  } catch (err) {
    console.error('[AUTH] Unexpected error during login', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

router.post('/logout', (req, res) => {
  res.clearCookie('token');
  return res.json({ message: 'Logged out' });
});

router.get('/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.userId).lean();
  if (!user) return res.status(404).json({ message: 'Not found' });
  return res.json({
    email: user.email,
    deviceIdHash: user.registeredDeviceIdHash,
    registeredAt: user.registeredAt,
  });
});

module.exports = router;


