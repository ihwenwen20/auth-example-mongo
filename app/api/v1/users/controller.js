const User = require('./model');

const { StatusCodes } = require('http-status-codes');
const { NotFoundError, BadRequestError, DuplicateError } = require('../../../errors');

module.exports = {
	getAllUsers: async (req, res, next) => {
		console.log('token', req.user)
		try {
			const skip = parseInt(req.query.skip) || 1;
			const limit = parseInt(req.query.limit) || 10;
			const search = req.query.s || '';
			// const offset = limit * skip;
			const selectFields = req.query.select;

			const totalRows = await User.countDocuments();
			const totalPage = Math.ceil(totalRows / limit);

			let query = {
				$or: [
					{ name: { $regex: search, $options: 'i' } },
					{ email: { $regex: search, $options: 'i' } }
				]
			};

			const projection = {}; // Define an empty projection object

			// If selectFields is provided, split the string and include only those fields in the projection
			if (selectFields) {
				const selectedFieldsArray = selectFields.split(',');
				selectedFieldsArray.forEach(field => {
					projection[field] = 1;
				});
			}

			const user = await User.find(query)
				.select(projection) // Apply the projection
				.lean()
				// .skip(offset)
				.skip(limit * (skip - 1))
				.limit(limit)
				.sort({ _id: -1 });

			const arrayUsers = user.map(arr => {
				const arrUser = { ...arr };
				delete arrUser.password;
				// delete arrUser.subscription;
				delete arrUser.refreshToken;
				delete arrUser.resetPasswordExpires;
				delete arrUser.resetPasswordToken;
				delete arrUser.__v;
				delete arrUser.otp;
				return arrUser;
			});

			const result = {
				statusCode: StatusCodes.OK, message: 'Get List Users Succes.',
				data: arrayUsers,
				limit,
				skip,
				totalRows,
				totalPage,
			};
			return res.status(StatusCodes.OK).json(result)
		} catch (error) {
			next(error)
		}
	},

	getUserById: async (req, res, next) => {
		try {
			const { id } = req.params;
			const user = await User.findOne({ _id: id })
			if (!user) throw new BadRequestError('Users Not Found');
			delete user._doc.password;
			delete user._doc.otp;
			delete user._doc.refreshToken;
			delete user._doc.resetPasswordExpires;
			delete user._doc.resetPasswordToken;
			delete user._doc.__v;
			return res.status(StatusCodes.OK).json({ statusCode: StatusCodes.OK, message: 'Get Details Users Success.', data: user });
		} catch (error) {
			next(error)
		}
	},

	createUser: async (req, res, next) => {
		try {
			const { username, email, password } = req.body;
			if (!username || !email || !password) throw new NotFoundError(username, email, password);

			const check = await User.findOne({ username, email });
			if (check) throw new DuplicateError(username, email);

			const users = await User.create({
				...req.body
			});

			delete users._doc.password;
			delete users._doc.otp;
			delete users._doc.refreshToken;
			delete users._doc.resetPasswordExpires;
			delete users._doc.resetPasswordToken;
			delete users._doc.__v;

			return res.status(StatusCodes.OK).json({ statusCode: StatusCodes.OK, message: 'Success!!! Users Created.', data: users })
		} catch (error) {
			next(error)
		}
	},

	updateUser: async (req, res, next) => {
		try {
			const { id } = req.params;
			const { username, email, password, confirmPassword, } = req.body;
			if (!username || !email || !password || !confirmPassword) throw new NotFoundError(username, email, password, confirmPassword);
			if (password !== confirmPassword) throw new BadRequestError('Password and Confirm Password do not match');

			const check = await User.findOne({
				username, email,
				_id: { $ne: id },
			});
			if (check) throw new DuplicateError(username, email);

			const users = await User.findOneAndUpdate(
				{ _id: id },
				{ ...req.body },
				{ new: true, runValidators: true }
			);
			if (!users) throw new BadRequestError('Users Not Found');

			delete users._doc.password;
			delete users._doc.otp;
			delete users._doc.__v;

			return res.status(StatusCodes.OK).json({ statusCode: StatusCodes.OK, message: 'Updated Data Users Successfully', data: users })
		} catch (error) {
			next(error)
		}
	},

	deleteUser: async (req, res, next) => {
		try {
			const { id } = req.params;
			if (id === req.user.userId) throw new BadRequestError('Warning!!! You cannot delete yourself.');

			const users = await User.findByIdAndDelete(id);
			if (!users) throw new BadRequestError('Users Not Found');

			return res.status(StatusCodes.OK).json({ statusCode: StatusCodes.OK, message: `Success!!! Users ${users.username} removed.`, data: {} })
		}
		catch (error) {
			next(error)
		}
	},

	updateUserProfile: async (req, res, next) => {
		try {
			const { username, email, password, confirmPassword, } = req.body;
			const userId = req.user.userId;

			if (!username || !email || !password || !confirmPassword) throw new NotFoundError(username, email, password, confirmPassword);
			if (password !== confirmPassword) throw new BadRequestError('Password and Confirm Password do not match');

			const user = await User.findById(userId);
			if (!user) throw new BadRequestError('Users Not Found');

			user.username = username;
			user.email = email;
			user.password = password;

			await user.save();
			return res.status(StatusCodes.OK).json({ statusCode: StatusCodes.OK, message: 'Success!!! Updated Data.', data: user });
		} catch (error) {
			next(error)
		}
	},

	extendSubscription: async (req, res, next) => {
		try {
			const userId = req.user._id;

			const user = await User.findById(userId);
			if (!user) throw new BadRequestError('Users Not Found');

			user.subscription.expiresAt = new Date();
			user.subscription.expiresAt.setMonth(user.subscription.expiresAt.getMonth() + 1);

			// Anda juga bisa memperbarui status langganan jika perlu
			// user.subscription.status = 'premium';

			await user.save();
			return res.status(StatusCodes.OK).json({ statusCode: StatusCodes.OK, message: 'Langganan berhasil diperpanjang.', data: user });
		} catch (error) {
			next(error)
		}
	},

	changeStatusUser: async (req) => {
		console.log('token', req.user)
		const { ids } = req.params;
		const secret = await Users.findOne({
			role: 'Developer'
		});
		if (!secret) {
			throw new UnauthorizedError('Bro, Lu mau ngapain hah :D ketauan kan... wkwk');
		}

		const { status } = req.body;
		if (!['Active', 'Inactive', 'Pending', 'Suspend', 'Free'].includes(status)) {
			throw new BadRequestError(`Status must be one of: 'Active', 'Inactive', 'Pending', 'Suspend', or 'Free'`);
		}

		const results = await Users.updateMany(
			{ _id: { $in: ids } },
			{ $set: { status } }
		);

		if (results.nModified === 0) {
			throw new BadRequestError('No Users were updated.');
		}

		// Clean sensitive data from the results.
		results.forEach(result => {
			delete result._doc.password;
			delete result._doc.otp;
		});

		return { statusCode: StatusCodes.OK, message: `Success! Updated status for ${results.length} users.`, data: results };
	}
}