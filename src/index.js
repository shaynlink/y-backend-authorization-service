require('dotenv').config();
const functions = require('@google-cloud/functions-framework');
const {SecretManagerServiceClient} = require('@google-cloud/secret-manager');
const { createPublicKey } = require('node:crypto');
const jwt = require('jsonwebtoken');

const SMClient = new SecretManagerServiceClient();

const latestSecretKey = {
  privateKey: null,
  publicKey: null,
  timestamp: null,
};

async function accessSecret() {
  if ((latestSecretKey.timestamp && Date.now() - latestSecretKey.timestamp < 300000) &&
      latestSecretKey.privateKey &&
      latestSecretKey.publicKey) {
    return [latestSecretKey.privateKey.toString(), latestSecretKey.publicKey.toString()];
  }

  const [secret] = await SMClient.accessSecretVersion({
    name: process.env.JWT_SECRET_NAME
  })

  const privateKey = secret.payload.data;
  
  const publicKey = createPublicKey(privateKey).export({
    type: 'spki',
    format: 'pem'
  })

  latestSecretKey.privateKey = privateKey;
  latestSecretKey.publicKey = publicKey;
  latestSecretKey.timestamp = Date.now();

  return [privateKey.toString(), publicKey.toString()];
}

accessSecret();

functions.http('authorization', async (req, res) => {
  if (!req.body || !req.body?.type) {
    return res.status(400).json({
      error: {
        message: 'Invalid request',
        missingFields: ['type']
      }
    });
  }

  const jwtOpt = {
    algorithm: ['RS256'],
    audience: 'y:services:*',
    issuer: 'y:services:authorization',
    subject: 'y:users:',
    expiresIn: '2 days',
    ignoreExpiration: false,
    ignoreNotBefore: false,
    clockTolerance: 10,
    allowInvalidAsymmetricKeyTypes: false
  }

  if (req.body.type === 'sign') {
    if (!req.body.userId) {
      return res.status(400).json({
        error: {
          message: 'Invalid request',
          missingFields: ['userId']
        }
      });
    }

    jwtOpt.subject += req.body.userId;

    const [privateKey] = await accessSecret();

    return res.status(200).json({
      error: null,
      result: {
        token: jwt.sign({}, privateKey, jwtOpt)
      }
    });
  } else if (req.body.type === 'verify') {
    if (!req.body.token) {
      return res.status(400).json({
        error: {
          message: 'Invalid request',
          missingFields: ['token']
        }
      });
    }

    const [_, publicKey] = await accessSecret();
    const verified = jwt.verify(req.body.token, publicKey, {
      issuer: jwtOpt.issuer,
    });

    return res.status(200).json({
      error: null,
      result: {
        verified
      }
    });
  }
})