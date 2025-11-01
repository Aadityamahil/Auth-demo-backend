const express = require('express');
const jwt = require('jsonwebtoken');
// base64url helper lib not needed; Node Buffer supports 'base64url' encoding
// const base64url = require('base64url');
// const { randomUUID } = require('crypto');
const User = require('../models/User');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const router = express.Router();

// Relying Party (RP) config
const rpName = process.env.WEBAUTHN_RP_NAME || 'Auth Demo';
const rpID = process.env.WEBAUTHN_RP_ID || 'localhost';
const origin = process.env.WEBAUTHN_ORIGIN || 'http://localhost:5173';

// In-memory challenge store for demo; in production, bind to user/session store
const challengeStore = new Map(); // key: email, value: challenge

router.post('/register/start', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email required' });

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: 'User not found' });

  // SimpleWebAuthn requires userID as a Buffer/Uint8Array (not string)
  const userIdBytes = Buffer.from(user._id.toString(), 'hex');

  const options = generateRegistrationOptions({
    rpName,
    rpID,
    userID: userIdBytes,
    userName: user.email,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
      authenticatorAttachment: 'platform', // prefer device-bound
    },
    excludeCredentials: user.webauthnCredentials.map((cred) => ({
      id: Buffer.from(cred.credentialID).toString('base64url'),
      type: 'public-key',
      transports: cred.transports || [],
    })),
  });

  // Normalize Buffer/Uint8Array fields to base64url strings for JSON transport
  const toB64Url = (val) => {
    if (!val) return val;
    if (typeof val === 'string') return val;
    try {
      return Buffer.from(val).toString('base64url');
    } catch (_) {
      return val;
    }
  };

  // Debug type of incoming challenge
  console.log('[WEBAUTHN] register/start raw challenge type:', typeof options.challenge, Array.isArray(options.challenge) ? 'array' : '');

  // Ensure challenge exists - generate if missing
  if (!options.challenge) {
    const rnd = require('crypto').randomBytes(32);
    options.challenge = rnd;
  }

  // Normalize challenge to Uint8Array for storage, base64url for browser
  // Note: In Node.js, Buffer extends Uint8Array, so check Buffer first
  let challengeForStorage;
  if (Buffer.isBuffer(options.challenge)) {
    // Convert Buffer to pure Uint8Array
    challengeForStorage = new Uint8Array(options.challenge);
  } else if (options.challenge instanceof Uint8Array && !Buffer.isBuffer(options.challenge)) {
    // Pure Uint8Array (not a Buffer)
    challengeForStorage = options.challenge;
  } else {
    // Convert other types (string, etc.) to Uint8Array
    const buf = Buffer.from(options.challenge);
    challengeForStorage = new Uint8Array(buf);
  }

  const normalized = {
    challenge: toB64Url(options.challenge),
    rp: { name: rpName, id: rpID },
    user: {
      id: toB64Url(userIdBytes),
      name: user.email,
      displayName: user.email,
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },   // ES256
      { type: 'public-key', alg: -257 }, // RS256
    ],
    timeout: 60000,
    attestation: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
      authenticatorAttachment: 'platform',
    },
    extensions: options.extensions || undefined,
    excludeCredentials: Array.isArray(options.excludeCredentials)
      ? options.excludeCredentials.map((cred) => ({
          type: 'public-key',
          id: toB64Url(cred.id),
          transports: cred.transports || [],
        }))
      : [],
  };

  // Temporary debug: log the keys sent to client (no secrets)
  console.log('[WEBAUTHN] register/start options keys:', Object.keys(normalized));

  // Debug: log what we're storing
  console.log('[WEBAUTHN] register/start - Storing challenge:', {
    array_length: challengeForStorage.length,
    type: challengeForStorage.constructor.name,
    is_buffer: Buffer.isBuffer(challengeForStorage),
    is_uint8array: challengeForStorage instanceof Uint8Array && !Buffer.isBuffer(challengeForStorage),
    b64url: Buffer.from(challengeForStorage).toString('base64url'),
    first_5_bytes: Array.from(challengeForStorage.slice(0, 5)),
  });

  challengeStore.set(email, challengeForStorage);
  return res.json(normalized);
});

router.post('/register/finish', async (req, res) => {
  const { email, attestationResponse } = req.body;
  if (!email || !attestationResponse) return res.status(400).json({ message: 'Missing fields' });

  const storedChallenge = challengeStore.get(email);
  if (!storedChallenge) return res.status(400).json({ message: 'No registration in progress' });

  // Convert stored challenge to base64url string
  // SimpleWebAuthn compares the challenge from clientDataJSON (which is base64url string)
  // with what we provide, so we should provide it as base64url string
  let challengeForVerification;
  let storedChallengeB64Url;
  
  if (Buffer.isBuffer(storedChallenge)) {
    storedChallengeB64Url = storedChallenge.toString('base64url');
  } else if (storedChallenge instanceof Uint8Array) {
    storedChallengeB64Url = Buffer.from(storedChallenge).toString('base64url');
  } else if (typeof storedChallenge === 'string') {
    storedChallengeB64Url = storedChallenge;
  } else {
    return res.status(400).json({ message: 'Invalid challenge format' });
  }

  // SimpleWebAuthn accepts challenge as base64url string or Uint8Array
  // Try passing as string since that's what clientDataJSON contains
  challengeForVerification = storedChallengeB64Url;

  // Debug: log challenge details for registration
  console.log('[WEBAUTHN] register/finish challenge:', {
    stored_type: storedChallenge?.constructor?.name || typeof storedChallenge,
    stored_is_buffer: Buffer.isBuffer(storedChallenge),
    challenge_format: typeof challengeForVerification,
    challenge_value: challengeForVerification.substring(0, 20) + '...',
    stored_b64url: storedChallengeB64Url,
  });

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: 'User not found' });

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge: challengeForVerification,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (e) {
    console.error('[WEBAUTHN] register/finish verification error:', {
      error_message: e.message,
      error_stack: e.stack,
      challenge_type: challengeForVerification.constructor.name,
      challenge_length: challengeForVerification.length,
      challenge_is_uint8array: challengeForVerification instanceof Uint8Array,
      challenge_is_buffer: Buffer.isBuffer(challengeForVerification),
    });
    return res.status(400).json({ 
      message: 'Registration verification failed',
      detail: e.message || String(e)
    });
  }

  const { verified, registrationInfo } = verification;
  if (!verified || !registrationInfo) return res.status(400).json({ message: 'Registration not verified' });

  // Extract credential ID from the attestation response (what browser sends)
  // This is the ID that will be used during authentication
  const credentialIDFromResponse = attestationResponse.id || attestationResponse.rawId;
  if (!credentialIDFromResponse) {
    return res.status(400).json({ message: 'Missing credential ID in attestation response' });
  }

  // Support both legacy and current SimpleWebAuthn shapes for public key
  const legacyCredentialPublicKey = registrationInfo.credentialPublicKey;
  const newCredential = registrationInfo.credential || {};
  const resolvedCredentialPublicKey = legacyCredentialPublicKey || newCredential.publicKey;
  const { fmt, aaguid } = registrationInfo;
  const counter = registrationInfo.counter || 0;

  if (!resolvedCredentialPublicKey) {
    console.warn('[WEBAUTHN] Missing credential public key', {
      hasCredentialPublicKey: Boolean(resolvedCredentialPublicKey),
      registrationInfoKeys: Object.keys(registrationInfo || {}),
    });
    return res.status(400).json({ message: 'Registration missing credential public key' });
  }

  // Ensure Buffer types for Mongo storage
  // Use the ID from the response, not from registrationInfo
  let credIDBuf;
  let credPubKeyBuf;
  try {
    credIDBuf = Buffer.from(credentialIDFromResponse, 'base64url');
    credPubKeyBuf = Buffer.isBuffer(resolvedCredentialPublicKey) ? resolvedCredentialPublicKey : Buffer.from(resolvedCredentialPublicKey);
  } catch (e) {
    console.error('[WEBAUTHN] Failed to convert credential buffers', e);
    return res.status(400).json({ message: 'Failed to process credential data' });
  }

  // Debug: log what we're storing
  const credIDB64Url = credIDBuf.toString('base64url');
  console.log('[WEBAUTHN] register/finish - Storing credential:', {
    credentialID_b64url: credIDB64Url,
    credentialID_length: credIDBuf.length,
  });

  // Ensure counter is a number (default to 0 for new credentials)
  const credentialCounter = typeof counter === 'number' ? counter : 0;

  const existing = user.webauthnCredentials.find((c) => c.credentialID.equals(credIDBuf));
  if (!existing) {
    user.webauthnCredentials.push({
      credentialID: credIDBuf,
      credentialPublicKey: credPubKeyBuf,
      counter: credentialCounter,
      fmt,
      aaguid,
      transports: attestationResponse.response.transports || [],
    });
    await user.save();
    console.log('[WEBAUTHN] register/finish - Credential saved successfully', { counter: credentialCounter });
  } else {
    console.log('[WEBAUTHN] register/finish - Credential already exists');
  }

  challengeStore.delete(email);
  return res.json({ verified: true });
});

router.post('/login/start', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email required' });

  const user = await User.findOne({ email });
  if (!user || user.webauthnCredentials.length === 0) {
    return res.status(404).json({ message: 'No credentials registered' });
  }

  const options = generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
    // Newer SimpleWebAuthn expects base64url string IDs here
    allowCredentials: user.webauthnCredentials.map((cred) => ({
      id: Buffer.from(cred.credentialID).toString('base64url'),
      type: 'public-key',
      transports: cred.transports,
    })),
  });

  // Normalize allowCredentials ids to base64url
  const toB64Url = (val) => {
    if (!val) return val;
    if (typeof val === 'string') return val;
    try { return Buffer.from(val).toString('base64url'); } catch (_) { return val; }
  };
  
  // Use the challenge from generateAuthenticationOptions (it generates its own)
  // Convert to Uint8Array format for consistency with SimpleWebAuthn
  let rawChallenge;
  if (!options.challenge) {
    // Fallback if library doesn't generate one (shouldn't happen)
    const rnd = require('crypto').randomBytes(32);
    rawChallenge = new Uint8Array(rnd);
  } else if (options.challenge instanceof Uint8Array) {
    rawChallenge = options.challenge;
  } else if (Buffer.isBuffer(options.challenge)) {
    rawChallenge = new Uint8Array(options.challenge);
  } else {
    // If it's a string or other format, convert to Uint8Array
    const buf = Buffer.from(options.challenge);
    rawChallenge = new Uint8Array(buf);
  }

  // Convert to base64url for browser
  const challengeB64Url = Buffer.from(rawChallenge).toString('base64url');

  // Debug: log challenge details
  console.log('[WEBAUTHN] login/start challenge:', {
    raw_length: rawChallenge.length,
    b64url: challengeB64Url,
    b64url_length: challengeB64Url.length,
  });

  const normalized = {
    challenge: challengeB64Url, // Send base64url to browser
    timeout: options.timeout,
    rpId: options.rpId || rpID,
    userVerification: options.userVerification,
    allowCredentials: Array.isArray(options.allowCredentials)
      ? options.allowCredentials.map((c) => ({ ...c, id: toB64Url(c.id) }))
      : [],
    extensions: options.extensions,
  };
  console.log('[WEBAUTHN] login/start options keys:', Object.keys(normalized));

  // Store the exact Uint8Array challenge we sent to browser
  challengeStore.set(email, rawChallenge);
  
  // Debug: Verify what we're storing
  console.log('[WEBAUTHN] login/start - Storing challenge:', {
    array_length: rawChallenge.length,
    b64url_sent_to_browser: challengeB64Url,
    first_5_bytes: Array.from(rawChallenge.slice(0, 5)),
    type: rawChallenge.constructor.name,
  });
  
  return res.json(normalized);
});

router.post('/login/finish', async (req, res) => {
  const { email, assertionResponse } = req.body;
  if (!email || !assertionResponse) return res.status(400).json({ message: 'Missing fields' });

  const expectedChallenge = challengeStore.get(email);
  if (!expectedChallenge) return res.status(400).json({ message: 'No login in progress' });

  // Convert stored challenge to base64url string
  // SimpleWebAuthn compares the challenge from clientDataJSON (which is base64url string)
  // with what we provide, so we should provide it as base64url string
  let challengeForVerification;
  let storedChallengeB64Url;
  
  if (Buffer.isBuffer(expectedChallenge)) {
    storedChallengeB64Url = expectedChallenge.toString('base64url');
  } else if (expectedChallenge instanceof Uint8Array) {
    storedChallengeB64Url = Buffer.from(expectedChallenge).toString('base64url');
  } else if (typeof expectedChallenge === 'string') {
    storedChallengeB64Url = expectedChallenge;
  } else {
    return res.status(400).json({ message: 'Invalid challenge format' });
  }

  // SimpleWebAuthn accepts challenge as base64url string or Uint8Array
  // Pass as string since that's what clientDataJSON contains
  challengeForVerification = storedChallengeB64Url;

  // Debug: log challenge comparison details
  console.log('[WEBAUTHN] login/finish challenge:', {
    stored_type: expectedChallenge?.constructor?.name || typeof expectedChallenge,
    challenge_format: typeof challengeForVerification,
    challenge_value: challengeForVerification.substring(0, 20) + '...',
    stored_b64url: storedChallengeB64Url,
  });

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: 'User not found' });

  // Validate assertionResponse structure
  if (!assertionResponse || !assertionResponse.id || !assertionResponse.response) {
    return res.status(400).json({ message: 'Invalid assertion response format' });
  }

  // Log response structure for debugging
  console.log('[WEBAUTHN] login/finish - Assertion response structure:', {
    has_id: !!assertionResponse.id,
    has_type: !!assertionResponse.type,
    has_rawId: !!assertionResponse.rawId,
    has_response: !!assertionResponse.response,
    response_keys: assertionResponse.response ? Object.keys(assertionResponse.response) : [],
    has_authenticatorData: !!assertionResponse.response?.authenticatorData,
    has_clientDataJSON: !!assertionResponse.response?.clientDataJSON,
    has_signature: !!assertionResponse.response?.signature,
  });

  const credentialIdBuf = Buffer.from(assertionResponse.id, 'base64url');
  const incomingCredIDB64Url = assertionResponse.id;
  
  // Debug: log what we're looking for vs what's stored
  console.log('[WEBAUTHN] login/finish - Looking for credential:', {
    incoming_credentialID_b64url: incomingCredIDB64Url,
    stored_credentials_count: user.webauthnCredentials.length,
    stored_credentialIDs: user.webauthnCredentials.map((c) => ({
      id_b64url: Buffer.from(c.credentialID).toString('base64url'),
      id_length: c.credentialID.length,
    })),
  });

  // Find matching credential - ensure we compare Buffers correctly
  const dbAuthenticator = user.webauthnCredentials.find((cred) => {
    const storedBuf = Buffer.isBuffer(cred.credentialID) ? cred.credentialID : Buffer.from(cred.credentialID);
    return storedBuf.equals(credentialIdBuf);
  });

  if (!dbAuthenticator) {
    console.warn('[WEBAUTHN] login/finish - Credential not found', {
      incoming_id: incomingCredIDB64Url,
      stored_ids: user.webauthnCredentials.map((c) => {
        const buf = Buffer.isBuffer(c.credentialID) ? c.credentialID : Buffer.from(c.credentialID);
        return buf.toString('base64url');
      }),
    });
    return res.status(404).json({ message: 'Unknown credential for user' });
  }
  
  console.log('[WEBAUTHN] login/finish - Credential found, verifying...');
  console.log('[WEBAUTHN] login/finish - Authenticator details:', {
    hasCredentialID: Boolean(dbAuthenticator.credentialID),
    hasCredentialPublicKey: Boolean(dbAuthenticator.credentialPublicKey),
    counter: dbAuthenticator.counter,
    counterType: typeof dbAuthenticator.counter,
    transports: dbAuthenticator.transports,
  });

  // Ensure counter exists (default to 0 if missing)
  const authenticatorCounter = typeof dbAuthenticator.counter === 'number' ? dbAuthenticator.counter : 0;

  // Convert Mongoose Buffers to Uint8Array for SimpleWebAuthn
  // SimpleWebAuthn expects credentialID and credentialPublicKey as Uint8Array
  // Note: Check Buffer first because Buffer extends Uint8Array
  let plainCredentialID;
  if (Buffer.isBuffer(dbAuthenticator.credentialID)) {
    plainCredentialID = new Uint8Array(dbAuthenticator.credentialID);
  } else if (dbAuthenticator.credentialID instanceof Uint8Array && !Buffer.isBuffer(dbAuthenticator.credentialID)) {
    plainCredentialID = dbAuthenticator.credentialID;
  } else {
    plainCredentialID = new Uint8Array(Buffer.from(dbAuthenticator.credentialID));
  }
  
  let plainCredentialPublicKey;
  if (Buffer.isBuffer(dbAuthenticator.credentialPublicKey)) {
    plainCredentialPublicKey = new Uint8Array(dbAuthenticator.credentialPublicKey);
  } else if (dbAuthenticator.credentialPublicKey instanceof Uint8Array && !Buffer.isBuffer(dbAuthenticator.credentialPublicKey)) {
    plainCredentialPublicKey = dbAuthenticator.credentialPublicKey;
  } else {
    plainCredentialPublicKey = new Uint8Array(Buffer.from(dbAuthenticator.credentialPublicKey));
  }

  // Construct authenticator object for SimpleWebAuthn
  // Use plain object literal (not Object.create(null)) to ensure proper prototype chain
  const authenticatorObj = {
    credentialID: plainCredentialID,
    credentialPublicKey: plainCredentialPublicKey,
    counter: Number(authenticatorCounter), // Ensure it's a Number, not just any number type
    transports: Array.isArray(dbAuthenticator.transports) ? [...dbAuthenticator.transports] : [],
  };

  // Validate the authenticator object before passing to SimpleWebAuthn
  if (!authenticatorObj.credentialID || !authenticatorObj.credentialPublicKey) {
    return res.status(400).json({ message: 'Invalid authenticator data' });
  }
  if (typeof authenticatorObj.counter !== 'number' || isNaN(authenticatorObj.counter)) {
    console.error('[WEBAUTHN] Invalid counter value:', authenticatorObj.counter);
    authenticatorObj.counter = 0; // Fallback to 0
  }

  console.log('[WEBAUTHN] login/finish - Authenticator object for verification:', {
    credentialID_type: authenticatorObj.credentialID.constructor.name,
    credentialID_length: authenticatorObj.credentialID.length,
    credentialID_is_uint8array: authenticatorObj.credentialID instanceof Uint8Array && !Buffer.isBuffer(authenticatorObj.credentialID),
    credentialPublicKey_type: authenticatorObj.credentialPublicKey.constructor.name,
    credentialPublicKey_length: authenticatorObj.credentialPublicKey.length,
    credentialPublicKey_is_uint8array: authenticatorObj.credentialPublicKey instanceof Uint8Array && !Buffer.isBuffer(authenticatorObj.credentialPublicKey),
    counter: authenticatorObj.counter,
    counter_type: typeof authenticatorObj.counter,
    counter_is_number: typeof authenticatorObj.counter === 'number',
    transports: authenticatorObj.transports,
    has_counter: 'counter' in authenticatorObj,
    keys: Object.keys(authenticatorObj),
  });

  let verification;
  try {
    // Ensure counter is a valid non-negative integer
    const finalCounter = typeof authenticatorObj.counter === 'number' && !isNaN(authenticatorObj.counter)
      ? Math.max(0, Math.floor(authenticatorObj.counter))
      : 0;

    // SimpleWebAuthn v13 uses 'credential' parameter, not 'authenticator'
    // Verify credentialID from response matches our stored credentialID
    const responseCredentialID = assertionResponse.id || assertionResponse.rawId;
    const storedCredentialIDB64 = Buffer.from(authenticatorObj.credentialID).toString('base64url');
    
    if (responseCredentialID !== storedCredentialIDB64) {
      console.error('[WEBAUTHN] Credential ID mismatch:', {
        response_id: responseCredentialID,
        stored_id: storedCredentialIDB64,
      });
      return res.status(400).json({ message: 'Credential ID mismatch' });
    }

    // Convert to Buffer format for credential (SimpleWebAuthn handles Buffers in Node.js)
    let credentialIDBuffer;
    let credentialPublicKeyBuffer;
    
    if (authenticatorObj.credentialID instanceof Uint8Array) {
      credentialIDBuffer = Buffer.from(authenticatorObj.credentialID);
    } else if (Buffer.isBuffer(authenticatorObj.credentialID)) {
      credentialIDBuffer = authenticatorObj.credentialID;
    } else {
      credentialIDBuffer = Buffer.from(authenticatorObj.credentialID);
    }

    if (authenticatorObj.credentialPublicKey instanceof Uint8Array) {
      credentialPublicKeyBuffer = Buffer.from(authenticatorObj.credentialPublicKey);
    } else if (Buffer.isBuffer(authenticatorObj.credentialPublicKey)) {
      credentialPublicKeyBuffer = authenticatorObj.credentialPublicKey;
    } else {
      credentialPublicKeyBuffer = Buffer.from(authenticatorObj.credentialPublicKey);
    }

    // Construct credential object for SimpleWebAuthn v13
    // SimpleWebAuthn expects: id (Uint8Array/Buffer), publicKey (Uint8Array/Buffer), counter (number)
    const credentialForVerification = {
      id: credentialIDBuffer,
      publicKey: credentialPublicKeyBuffer,
      counter: finalCounter,
    };

    // Add transports only if present (optional field)
    if (authenticatorObj.transports && Array.isArray(authenticatorObj.transports) && authenticatorObj.transports.length > 0) {
      credentialForVerification.transports = authenticatorObj.transports;
    }

    // Construct verification params - SimpleWebAuthn v13 expects 'credential', not 'authenticator'
    const verificationParams = {
      response: assertionResponse,
      expectedChallenge: challengeForVerification,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: credentialForVerification,
    };

    // Final log before verification
    console.log('[WEBAUTHN] login/finish - Final verification params:', {
      has_response: !!verificationParams.response,
      has_expectedChallenge: !!verificationParams.expectedChallenge,
      has_expectedOrigin: !!verificationParams.expectedOrigin,
      has_expectedRPID: !!verificationParams.expectedRPID,
      has_credential: !!verificationParams.credential,
      credential_id_type: verificationParams.credential.id.constructor.name,
      credential_id_length: verificationParams.credential.id.length,
      credential_publicKey_type: verificationParams.credential.publicKey.constructor.name,
      credential_publicKey_length: verificationParams.credential.publicKey.length,
      credential_counter: verificationParams.credential.counter,
      credential_counter_type: typeof verificationParams.credential.counter,
      credential_has_counter: 'counter' in verificationParams.credential,
    });

    verification = await verifyAuthenticationResponse(verificationParams);
  } catch (e) {
    console.error('[WEBAUTHN] verifyAuthenticationResponse error:', {
      message: e.message,
      stack: e.stack,
      name: e.name,
    });
    return res.status(400).json({ message: 'Authentication verification failed', detail: String(e && e.message || e) });
  }

  const { verified, authenticationInfo } = verification;
  if (!verified || !authenticationInfo) return res.status(401).json({ message: 'Not verified' });

  // Update counter to prevent replay
  if (dbAuthenticator) {
    dbAuthenticator.counter = authenticationInfo.newCounter;
    await user.save();
  }

  challengeStore.delete(email);

  // Issue session cookie like password login
  const token = jwt.sign(
    { userId: user._id, email: user.email },
    process.env.JWT_SECRET || 'dev_secret',
    { expiresIn: '15m' }
  );
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie('token', token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'strict',
    maxAge: 15 * 60 * 1000,
  });

  return res.json({ verified: true });
});

module.exports = router;


