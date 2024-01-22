const mongoose = require('mongoose');
const argon2 = require('argon2');

const userSchema = new mongoose.Schema({
	username: {
		type: String,
		trim: true,
		minlength: 2,
		unique: [true, "UserName Already Exist"],
		required: [true, 'Please provide name'],
	},
	email: {
		type: String,
		trim: true,
		unique: [true, "Email Already Exist"],
		required: [true, 'Please provide email'],
	},
	password: {
		type: String,
		trim: true,
		minlength: 6,
		required: [true, 'Password is required'],
	},
	refreshToken: String,
	otp: {
		type: String,
		required: true,
		default: () => Math.floor(Math.random() * 999999) + new Date().getTime() % 999999,
	},
	status: {
		type: String,
		enum: ['Active', 'Inactive'],
		default: 'Inactive',
	},
	isAdmin: {
		type: Boolean,
		default: false,
	},
	subscription: {
		status: {
			type: String,
			enum: ['basic', 'premium', 'pro'],
			default: 'basic',
		},
		expiresAt: {
			type: Date,
			default: () => new Date().setMonth(new Date().getMonth() + 1),
		},
	},
	resetPasswordToken: String,
	resetPasswordExpires: Date,
});

userSchema.path('email').validate(
	function (value) {
		// eslint-disable-next-line no-useless-escape
		// # Local
		const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
		// # Prod
		// const EMAIL_RE = /^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/;
		return EMAIL_RE.test(value);
	},
	(attr) => `${attr.value} Invalid email format!`
);

userSchema.pre('save', async function (next) {
	const User = this;
	if (User.isModified('password')) {
		try {
			const hashedPassword = await argon2.hash(User.password);
			User.password = hashedPassword;
		} catch (error) {
			throw new Error('Failed to encrypt password');
		}
	}
	next();
});

userSchema.methods.comparePassword = async function (candidatePassword) {
	try {
		const isMatch = await argon2.verify(this.password, candidatePassword);
		return isMatch;
	} catch (error) {
		throw new Error('Failed to compare password');
	}
};

module.exports = mongoose.model('User', userSchema);

