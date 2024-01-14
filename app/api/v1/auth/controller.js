const User = require('../users/model');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Brevo = require('@getbrevo/brevo');
const { NotFoundError, BadRequestError, UnauthorizedError, DuplicateError } = require("../../../errors");
const config = require('../../../config')
const template_verifyEmail = require('../../../views/template-verifyemail1')
const template_resetpassword = require('../../../views/template-resetpassword')

exports.register = async (req, res, next) => {
	try {
		const { username, email, password, confirmPassword } = req.body;
		if (!username || !email || !password || !confirmPassword) throw new NotFoundError(username, email, password, confirmPassword);
		if (password !== confirmPassword) throw new BadRequestError('Password and Confirm Password do not match');

		const check = await User.findOne({ username, email });
		if (check) throw new DuplicateError(username, email);

		const isFirstAccount = (await User.countDocuments({})) === 0;
		const admin = isFirstAccount ? true : false;
		const user = new User({
			...req.body, isAdmin: admin,
		});
		await user.save();

		delete user._doc.password;
		delete user._doc.isAdmin;
		delete user._doc.subscription;
		delete user._doc._id;
		delete user._doc.__v;
		delete user._doc.otp;

		// 	let checkMail = await User.findOne({
		// 		email,
		// 		status: "Inactive",
		// 	});
		// 	await otpMail(email, checkMail);

		if (!user.isAdmin || user.email !== config.brevo_email) {
			const token = crypto.randomBytes(20).toString('hex');
			let apiInstance = new Brevo.TransactionalEmailsApi();
			apiInstance.setApiKey(Brevo.AccountApiApiKeys.apiKey, config.brevo_key)
			let sendSmtpEmail = new Brevo.SendSmtpEmail();
			sendSmtpEmail = {
				subject: '{{params.subject}}',
				sender: { name: `${config.brevo_name}`, email: `${config.brevo_email}` },
				to: [{
					email: user.email,
					name: user.username
				}],
				replyTo: { name: `${config.brevo_name}`, email: `${config.brevo_email}` },
				// templateId: 4,
				params: {
					appName: `${config.appName}`,
					subject: 'Verify Email',
					username: user.username,
					url_button: `${config.URLAPP}/verifyemail/${token}`,
				},
				headers: {
					'X-Mailin-custom': 'custom_header_1:custom_value_1|custom_header_2:custom_value_2'
				},
				htmlContent: template_verifyEmail,
			};
			let sendEmail = await apiInstance.sendTransacEmail(sendSmtpEmail).then(function (data) {
				// console.log('API called sendTransacEmail successfully. Returned data: ' + JSON.stringify(data));
				return res.status(data.response.statusCode).json({ statusCode: data.response.statusCode, message: 'An Email with a verication link has been send to your email.' });
			}).catch(function (error) {
				return res.status(error.statusCode).json({ statusCode: error.statusCode, body: error.body.code, message: `Failed to send email: ${error.body.message}` });
			})
			return sendEmail
		}

		return res.status(201).json({
			message: 'Register Success!!! Please Activated Account from your email.',
			data: user,
		});
	} catch (error) {
		next(error)
	}
};

exports.login = async (req, res, next) => {
	try {
		const { email, password } = req.body;
		if (!email || !password) {
			return res.status(400).send('Please Provide All Field...');
		}

		let user;

		if (email.includes('@')) {
			user = await User.findOne({ email: email });
		} else {
			user = await User.findOne({ username: email });
		}

		if (!user) throw new UnauthorizedError('Invalid Credentials, Please Activated Account');

		const isPasswordCorrect = await user.comparePassword(password);
		if (!isPasswordCorrect) throw new UnauthorizedError('Invalid Credentials');

		const accessToken = jwt.sign({
			userId: user._id, username: user.username, email: user.email, isAdmin: user.isAdmin,
		}, config.secretKey, {
			expiresIn: config.jwtExpiration,
		});

		const refreshToken = jwt.sign({
			userId: user._id, username: user.username, email: user.email, isAdmin: user.isAdmin,
		}, config.secretKey, {
			expiresIn: config.jwtRefreshTokenExpiration,
		});
		user.refreshToken = refreshToken;
		await user.save();

		const result = { accessToken, refreshToken, userId: user._id, username: user.username, email: user.email, password: user.password }
		return res.status(200).json({ message: `Hi, ${user.username}. Welcome To WeA Gate :)`, data: result });
	} catch (error) {
		next(error)
	}
};

exports.refreshToken = async (req, res, next) => {
	try {
		const { refreshToken } = req.body;
		const decoded = jwt.verify(refreshToken, config.secretKey);

		const user = await User.findById(decoded.userId);
		if (!user || user.refreshToken !== refreshToken) throw new BadRequestError('Invalid Refresh Token')

		const accessToken = jwt.sign({
			userId: user._id, username: user.username, email: user.email, isAdmin: user.isAdmin,
		}, config.secretKey, {
			expiresIn: config.jwtExpiration,
		});

		res.json({ accessToken });
	} catch (error) {
		next(error)
	}
};

exports.logout = async (req, res, next) => {
	try {
		const userId = req.user.userId;

		const user = await User.findById(userId);
		if (!user) throw new BadRequestError('Users Not Found');

		user.refreshToken = null;
		await user.save();

		return res.status(200).json({ message: 'Logout success!' });
	} catch (error) {
		next(error)
	}
};

exports.forgotPassword = async (req, res, next) => {
	try {
		const { email } = req.body;
		if (!email) throw new BadRequestError('Email is required');
		const user = await User.findOne({ email });
		if (!user) throw new BadRequestError('Users Not Found');

		const token = crypto.randomBytes(20).toString('hex');
		const expiresIn = new Date();
		expiresIn.setHours(expiresIn.getHours() + 1); // Token kadaluwarsa dalam 1 jam
		user.resetPasswordToken = token;
		user.resetPasswordExpires = expiresIn;
		await user.save();

		let apiInstance = new Brevo.TransactionalEmailsApi();
		apiInstance.setApiKey(Brevo.AccountApiApiKeys.apiKey, config.brevo_key)

		let sendSmtpEmail = new Brevo.SendSmtpEmail();
		// htmlContent = "<html><body><h1>Common: Hi, {{params.username}} This is my first transactional email. linkTitle: {{params.linkTitle}} url: {{params.url_button}}</h1></body></html>";

		sendSmtpEmail = {
			subject: '{{params.subject}}',
			sender: { name: `${config.brevo_name}`, email: `${config.brevo_email}` },
			to: [{
				email: user.email,
				name: user.username
			}],
			replyTo: { name: `${config.brevo_name}`, email: `${config.brevo_email}` },
			// templateId: 3,
			headers: {
				'X-Mailin-custom': 'custom_header_1:custom_value_1|custom_header_2:custom_value_2'
			},
			params: {
				appName: `${config.appName}`,
				subject: 'Reset Password',
				username: user.username,
				url_button: `${config.URLAPP}/reset-password/${token}`,
			},
			htmlContent: template_resetpassword,
		};

		let sendEmail = await apiInstance.sendTransacEmail(sendSmtpEmail).then(function (data) {
			// console.log('API called sendTransacEmail successfully. Returned data: ' + JSON.stringify(data));
			return res.status(data.response.statusCode).json({ statusCode: data.response.statusCode, message: 'Email reset password was send.' });
		}).catch(function (error) {
			return res.status(error.statusCode).json({ statusCode: error.statusCode, body: error.body.code, message: `Failed to send email: ${error.body.message}` });
		})

		return sendEmail
	} catch (error) {
		next(error)
	}
};

exports.resetPassword = async (req, res, next) => {
	try {
		const { password, confirmPassword } = req.body;
		if (password !== confirmPassword) throw new BadRequestError('Password and Confirm Password does no match');

		const { token } = req.params;
		const user = await User.findOne({
			resetPasswordToken: token,
			resetPasswordExpires: { $gt: Date.now() },
		});

		if (!user) throw new BadRequestError('Token reset password tidak valid atau sudah kadaluwarsa.');

		const isSamePassword = await user.comparePassword(password);
		if (isSamePassword) throw new BadRequestError('Kata sandi baru harus berbeda dengan kata sandi lama.');

		user.password = password;
		user.resetPasswordToken = null;
		user.resetPasswordExpires = null;
		await user.save();

		return res.status(200).json({ message: 'God job!!! Reset Password successfully.' });
	} catch (error) {
		next(error)
	}
};
