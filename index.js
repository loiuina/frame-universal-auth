const jwt = require('jsonwebtoken');

class UniversalAuth {
  constructor(options) {
    this.options = options;
  }

  basic(username, password) {
    const token = Buffer.from(`${username}:${password}`).toString('base64');
    return `Basic ${token}`;
  }

  jwtSign(payload) {
    if (!this.options.jwtSecret) {
      throw new Error('JWT secret not provided.');
    }
    return jwt.sign(payload, this.options.jwtSecret, { expiresIn: '1h' });
  }

  jwtVerify(token) {
    if (!this.options.jwtSecret) {
      throw new Error('JWT secret not provided.');
    }
    try {
      return jwt.verify(token, this.options.jwtSecret);
    } catch (error) {
      return null; // or handle error as per your application's error handling policy
    }
  }
}

module.exports = UniversalAuth;