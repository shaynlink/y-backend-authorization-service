const functions = require('@google-cloud/functions-framework');
const {SecretManagerServiceClient} = require('@google-cloud/secret-manager');
const { createPublicKey } = require('node:crypto');
const jwt = require('jsonwebtoken');

const ISSUER = 'y:services:authorization';

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
  if (!req.body || !req.body?.type) {
    return res.status(400).json({
      error: {
        message: 'Invalid request',
        missingFields: ['type']
      }
    });
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

    const jwtOptSign = {
      algorithm: 'RS256',
      // y:internal (admin user), y:services (regular user), y:external (using from external service like APIs)
      audience: 'y:services:*',
      issuer: ISSUER,
      // y:users (regular user), y:bots (bot user)
      subject: 'y:users:' + req.body.userId,
      expiresIn: '2 days',
      allowInvalidAsymmetricKeyTypes: false,
      allowInsecureKeySizes: false
    }

    const [privateKey] = await accessSecret();

    return res.status(200).json({
      error: null,
      result: {
        token: jwt.sign({}, privateKey, jwtOptSign)
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

    const jwtOptVerify = {
      issuer: ISSUER,
      ignoreExpiration: false,
      ignoreNotBefore: false,
      clockTolerance: 30,
      maxAge: '3 days',
    }

    const [_, publicKey] = await accessSecret();
    try {
      const decoded = jwt.verify(req.body.token, publicKey, jwtOptVerify);
      return res.status(200).json({
        error: null,
        result: {
          valide: false,
          decoded
        }
      });
    } catch {
      return res.status(401).json({
        error: {
          message: 'Invalid token'
        }
      });
    }
  }
})