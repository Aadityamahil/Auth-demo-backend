const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, index: true },
    passwordHash: { type: String, required: true },
    registeredDeviceIdHash: { type: String, default: null },
    registeredAt: { type: Date, default: null },
    webauthnCredentials: {
      type: [
        new mongoose.Schema(
          {
            credentialID: { type: Buffer, required: true },
            credentialPublicKey: { type: Buffer, required: true },
            counter: { type: Number, default: 0 },
            transports: { type: [String], default: [] },
            fmt: { type: String, default: null },
            aaguid: { type: String, default: null },
          },
          { _id: false }
        ),
      ],
      default: [],
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('User', userSchema);


