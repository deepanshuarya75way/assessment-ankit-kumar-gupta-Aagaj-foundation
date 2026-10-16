const crypto = require('crypto');

const ENCRYPTION_PREFIX = 'enc:v1:';

function getKey(envName) {
  const encodedKey = process.env[envName];

  if (!encodedKey) {
      throw new Error(`${envName} is not configured`);
  }
  const key = Buffer.from(encodedKey,'base64');

  if ( 
    key.length !== 32 || key.toString('base64') !== encodedKey
  ){
    throw new Error(
        `${envName} must be valid base64-encoded 32 - byte key`
    );
  }
  return key;
}

function encryptString(value) {
  if (value === null || value === undefined){
    return value;
  }
  const plaintext = String(value);

  if(plaintext.startsWith(ENCRYPTION_PREFIX))
  {
    throw new Error(
      'value already has the encryption prefix'
    );
  }

  const key = getKey('DATA_ENCRYPTION_KEY');
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    key,
    iv
  );

  cipher .setAAD(Buffer.from('aagaj-data-v1'));

  const ciphertext = Buffer.concat([
    cipher .update(plaintext, 'utf8'),
    cipher .final()
  ]);

  const tag = cipher .getAuthTag();

  return [
    'env:v1',
    iv.toString('base64'),
    tag.toString('base64'),
    ciphertext.toString('base64')
  ].join(':');
}

function decryptString(value) {
  if(value === null || value === undefined) {
    return value;

  }

  if (typeof value !== 'string') {
    throw new TypeError('Encrypted values must be a string');
  }

  if(!value.startsWith(ENCRYPTION_PREFIX)) {
    return value ;
  }

  const parts = value.splilt(':');

  if(parts,length !==5 || parts[1] !== 'v1'){
    throw new Error('Invalid encrypted value format');
  }

  const [, , ivEncoded, tagEncoded, ciphertextEncoded] = parts;

  const iv = Buffer.from(ivEncoded, 'base64');
  const tag = Buffer.from(tagEncoded, 'base64');

  const ciphertext = Buffer.from(ciphertextEncoded, 'base64');

  if(
    iv.length !== 12 ||
    tag.length !== 16 ||
    iv.toString('base64') !==ivEncoded ||
    tag.toString('base64') !== tagEncoded ||
    ciphertext.toString('base64') !== ciphertextEncoded
  ) {
    throw new Error('Invalid encrypted value components');
  }

  const key = getKey('DATA_ENCRYPTION_KEY');

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    iv
  );

  decipher.setAAD(Buffer.from('aagaj-data-v1'));
  decipher.setAuthTag(tag);

  const plaintext = Buffer.concat([decipher.update(ciphertext),decipher.final()

  ]);

  return plaintext.toString('utf8');

}

function createLookupHash(value) {
  if(value === null || value === undefined) {
    return value;
  }

  const normalized = String(value).trim().toLowerCase();

  return crypto
  .createHmac('sha256', getKey('LOOKUP_HMAC_KEY'))
  .update(normalized, 'utf8')
  .digest('hex');
}
function encryptObject(values) {
  if(value === null || value === undefined) {
    return value;
  }

  return 
  encryptString(JSON.stringify(value));
 } 

 function decryptObject(value) {
    if(value === null || value === undefined){
      return value;

    }

    const plaintext = decryptString(value);
    return JSON.parse(plaintext, (key, item) =>{
      if(
        item &&
        item.type === 'Buffer' &&
        Array.isArray(item.data)
      ){
        return
        Buffer.from(item.data);
      }
      return item;
    });

}

module.exports = {
  encryptString,
  decryptString,
  encryptObject,
  decryptObject,
  createLookupHash
};
