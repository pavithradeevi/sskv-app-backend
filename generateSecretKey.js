// generateSecretKey.js
const crypto = require('crypto');

// Generate a random secret key with 256-bit strength (32 bytes)
const secretKey = crypto.randomBytes(32).toString('hex');

console.log('Generated JWT Secret Key:', secretKey);
