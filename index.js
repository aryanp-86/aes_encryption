const express = require('express');
const crypto = require('crypto');
const AWS = require('aws-sdk');
require('dotenv').config();

const app = express();
const port = 3000;

// Configure AWS SDK with environment variables
AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION
});

const kms = new AWS.KMS();

// Generate or retrieve a data key from AWS KMS
let dataKey;
let encryptedDataKey;

kms.generateDataKey({
  KeyId: process.env.KMS_KEY_ID,
  KeySpec: 'AES_256'
}, (err, data) => {
  if (err) {
    console.error('Error generating data key:', err);
    return;
  }

  dataKey = data.Plaintext;
  encryptedDataKey = data.CiphertextBlob;
  console.log('Data key retrieved from AWS KMS');

  // Start the server after retrieving the data key
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
});

app.use(express.json());

// Route for encrypting data using AES
app.post('/encrypt', (req, res) => {
  const plaintext = req.body.plaintext;
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv('aes-256-cbc', dataKey, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const encryptedData = `${iv.toString('hex')}:${encrypted}`;

  res.json({ encryptedData, encryptedDataKey: encryptedDataKey.toString('base64') });
});

// Route for decrypting data using AES
app.post('/decrypt', (req, res) => {
  const { encryptedData, encryptedDataKey } = req.body;
  const [ivHex, encrypted] = encryptedData.split(':');
  const iv = Buffer.from(ivHex, 'hex');

  kms.decrypt({
    CiphertextBlob: Buffer.from(encryptedDataKey, 'base64')
  }, (err, data) => {
    if (err) {
      console.error('Error decrypting data key:', err);
      return res.status(500).json({ error: 'Error decrypting data key' });
    }

    const plaintextKey = data.Plaintext;

    const decipher = crypto.createDecipheriv('aes-256-cbc', plaintextKey, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    res.json({ decrypted });
  });
});