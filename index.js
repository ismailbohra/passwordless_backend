const express = require("express");
const mongoose = require("mongoose");
const User = require("./models/user.model");
const app = express();
require("dotenv").config();
const SimpleWebAuthnServer = require("@simplewebauthn/server");
const PORT = 4000;

var cors = require("cors");
app.use(cors());
app.use(express.json());

const crypto = require("node:crypto");
if (!globalThis.crypto) {
  globalThis.crypto = crypto;
}

mongoose.connect(process.env.DB_URL).then(() => {
  console.log("Connected to MongoDB");
  app.listen(PORT, () => {
    console.log(`Listening to port ${PORT}`);
  });
});

app.post("/register", async (req, res) => {
  try {
    const option = await SimpleWebAuthnServer.generateRegistrationOptions({
      rpID: "localhost",
      rpName: "My Localhost Machine",
      attestationType: "none",
      timeout: 30_000,
      userName: req.body.username,
    });

    let user = await User.create({
      username: req.body.username,
      challenge: option.challenge,
    });
    if (!user) {
      res.status(500).send({ msg: "internal server error" });
    }
    res.status(200).send({ user, option });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }
});

app.post("/verifyregister", async (req, res) => {
  const user = await User.findOne({ username: req.body.username });

  try {
    let verification = await SimpleWebAuthnServer.verifyRegistrationResponse({
      expectedChallenge: user.challenge,
      expectedOrigin: req.body.origin,
      expectedRPID: "localhost",
      response: req.body.attResp,
    });

    if (verification.verified) {
      user.status = true;
      (user.passkey = verification.registrationInfo), await user.save();
    }
    console.log("passkey before saving ->", verification.registrationInfo);
    const { verified } = verification;
    res.status(200).send({ verified });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }
});

app.post("/login", async (req, res) => {
  const { username } = req.body;

  const user = await User.findOne({ username });

  if (!user) return res.status(404).json({ error: "user not found!" });

  const opts = await SimpleWebAuthnServer.generateAuthenticationOptions({
    rpID: "localhost",
  });
  user.challenge = opts.challenge;
  await user.save();
  return res.json({ options: opts });
});

app.post("/loginverify", async (req, res) => {
  try {
    const { username, cred, origin } = req.body;

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const challenge = user.challenge;

    const opt = {
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: "localhost",
      response: cred,
      authenticator: {
        ...user.passkey,
        credentialPublicKey: new Uint8Array(
          user.passkey.credentialPublicKey.buffer
        ),
        attestationObject: new Uint8Array(
          user.passkey.attestationObject.buffer
        ),
      },
    };
    const verification =
      await SimpleWebAuthnServer.verifyAuthenticationResponse(opt);

    if (!verification.verified) {
      return res.status(400).json({ error: "Verification failed" });
    }

    res.status(200).json({ verified: true });
  } catch (error) {
    console.error("Login verification error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
