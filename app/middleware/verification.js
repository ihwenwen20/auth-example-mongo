const { UnauthenticatedError, UnauthorizedError } = require('../errors');
const dotenv = require('dotenv');
dotenv.config();

const jwt = require('jsonwebtoken');
const secretKey = process.env.JWT_SECRET_KEY;

// module.exports = {
// 	isAdmin: (req, res, next) => {
// 		if (req.user && req.user.isAdmin) {
// 			next();
// 		} else {
// 			throw new UnauthorizedError('Unauthorized to Access This Route');
// 		}
// 	},

// 	// authenticate: (req, res, next) => {
// 	// 	let token;
// 	// 	const accessToken = req.header('Authorization');
// 	// 	// console.log('accessToken',req.header('Authorization'));

// 	// 	if (accessToken && accessToken.startsWith('Bearer')) {
// 	// 		token = accessToken.split(' ')[1];
// 	// 	}

// 	// 	if (!token) {
// 	// 		throw new UnauthenticatedError('Access Denied. No token provided.');
// 	// 	}

// 	// 	// const token = accessToken.split(' ')[1];

// 	// 	try {
// 	// 		const decoded = jwt.verify(token, secretKey);
// 	// 		req.user = decoded;
// 	// 		next();
// 	// 	} catch (error) {
// 	// 		throw new UnauthenticatedError('Invalid Authentication.');
// 	// 	}
// 	// }
// 	authenticate: (req, res, next) => {
// 		let token;
// 		const accessToken = req.headers['authorization'];
// 		const refreshToken = req.cookies['refreshToken'];
// 		// console.log('accessToken1', req.header['authorization']);
// 		// console.log('refreshToken1', req.cookies['refreshToken']);
// 		if (!accessToken || accessToken === undefined && !refreshToken || refreshToken === undefined) {
// 			throw new UnauthenticatedError('Access Denied. No token provided.');
// 		}

// 		if (accessToken && accessToken.startsWith('Bearer')) {
// 			token = accessToken.split(' ')[1];
// 		}
// 		// console.log('token', token)

// 		// const token = accessToken.split(' ')[1];

// 		try {
// 			const decoded = jwt.verify(token, secretKey);
// 			// console.log('decoded1', decoded)
// 			req.user = decoded;
// 			next();
// 		} catch (err) {
// 			// console.log('error auth', error)
// 			if (err instanceof jwt.JsonWebTokenError || err instanceof jwt.TokenExpiredError) {
// 				console.log('err', err.message)
// 				throw new UnauthenticatedError(`Access Denied. ${err.message}.`);
// 			}
// 			if (!refreshToken || refreshToken === undefined) {
// 				throw new UnauthenticatedError('Access Denied. No token provided.')
// 			}
// 			// console.log('refreshToken', refreshToken)
// 			try {
// 				const decoded = jwt.verify(refreshToken, secretKey);
// 				// console.log('decoded2', decoded)
// 				const result = { userId: decoded._id, username: decoded.username, email: decoded.email }
// 				// const accessToken = jwt.sign(result, secretKey, { expiresIn: '1h' });

// 				return res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: 'strict' })
// 					// .header('Authorization', accessToken)
// 					.send(result);
// 			} catch (error) {
// 				throw new UnauthenticatedError('Invalid Authentication.');
// 			}
// 		}
// 	}
// }

const tokenBlacklist = [];

module.exports = {
  isAdmin: (req, res, next) => {
    if (req.user && req.user.isAdmin) {
      next();
    } else {
      throw new UnauthorizedError('Unauthorized to Access This Route');
    }
  },

  authenticate: (req, res, next) => {
    let token;
    const accessToken = req.headers['authorization'];
    const refreshToken = req.cookies['refreshToken'];

    if (!accessToken || accessToken === undefined || !refreshToken || refreshToken === undefined) {
      throw new UnauthenticatedError('Access Denied. No token provided.');
    }

    if (accessToken && accessToken.startsWith('Bearer')) {
      token = accessToken.split(' ')[1];
    }

    try {
      if (tokenBlacklist.includes(token)) {
        throw new UnauthenticatedError('Token has been invalidated.');
      }

      const decoded = jwt.verify(token, secretKey);
      req.user = decoded;
      next();
    } catch (err) {
      if (err instanceof jwt.JsonWebTokenError || err instanceof jwt.TokenExpiredError) {
        // Handle token expiration or invalid token
        throw new UnauthenticatedError(`Access Denied. ${err.message}.`);
      }

      // Handle refresh token logic here if needed

      throw new UnauthenticatedError('Invalid Authentication.');
    }
  },

  addToBlacklist: (token) => {
    // Add the token to the blacklist
    tokenBlacklist.push(token);
  },
};