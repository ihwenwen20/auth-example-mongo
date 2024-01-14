const dotenv = require('dotenv');
dotenv.config();

module.exports = {
	jwtExpiration: process.env.JWT_EXPIRATE_TOKEN,
	jwtRefreshTokenExpiration: process.env.JWT_EXPIRATE_REFRESH_TOKEN,
	secretKey: process.env.JWT_SECRET_KEY,
	URLAPP: `${process.env.HOST}:${process.env.PORT}`,
	host: `${process.env.HOST} || http://localhost`,
	port: `${process.env.PORT}`,
	log: {
		level: "silent",
		// logger: ["console", "file"],
		logger: [],
	},
	urlDb: `${process.env.MONGO_URL}`,
	brevo_key: `${process.env.BREVO_KEY}`,
	brevo_name: `${process.env.BREVO_NAME}`,
	brevo_email: `${process.env.BREVO_EMAIL}`,
	appName: `${process.env.APP_NAME}`,
};
