const brevo = require('@getbrevo/brevo');

let apiInstance = new brevo.TransactionalEmailsApi();
apiInstance.setApiKey(brevo.AccountApiApiKeys.apiKey, config.brevo_key)

let sendSmtpEmail = new brevo.SendSmtpEmail();
htmlContent = "<html><body><h1>Common: Hi, {{params.username}} This is my first transactional email. linkTitle: {{params.linkTitle}} url: {{params.url_button}}</h1></body></html>";

sendSmtpEmail = {
	subject: '{{params.subject}}',
	htmlContent: htmlContent,
	// sender: { name: user.username, email: user.email },
	to: [{
		email: user.email,
		name: user.username
	}],
	replyTo: {
		email: user.email,
		name: user.username
	},
	// templateId: 3,
	headers: {
		'X-Mailin-custom': 'custom_header_1:custom_value_1|custom_header_2:custom_value_2'
	},
	params: {
		username: user.username,
		url_button: `${config.URLAPP}/reset-password/${token}`,
		linkTitle: 'Reset Password',
		subject: 'Reset Password'
	},
};

let sendEmail = apiInstance.sendTransacEmail(sendSmtpEmail).then(function (data) {
	console.log('API called sendTransacEmail successfully. Returned data: ' + JSON.stringify(data));
}, function (error) {
	console.error('error', error.body);
	console.error('error.code', error.code);
	console.error('error.message', error.message);
});
console.log('sendEmail', sendEmail)



/* Asyncronous */
/*
const brevo = require('@getbrevo/brevo');

// Fungsi async yang akan mengirim email
const sendTransactionalEmail = async (user, token) => {
		try {
				let apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
		apiInstance.setApiKey(SibApiV3Sdk.AccountApiApiKeys.apiKey, config.brevo_key)

		let sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
		// htmlContent = "<html><body><h1>Common: Hi, {{params.username}} This is my first transactional email. linkTitle: {{params.linkTitle}} url: {{params.url_button}}</h1></body></html>";

		sendSmtpEmail = {
			subject: '{{params.subject}}',
			sender: { name: `${config.brevo_name}`, email: `${config.brevo_email}` },
			to: [{
				email: user.email,
				name: user.username
			}],
			replyTo: {
				email: user.email,
				name: user.username
			},
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
			htmlContent: template_verifyEmail,
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

// Panggil fungsi untuk mengirim email
const user = { username: 'exampleUser', email: 'example@example.com' }; // Gantilah dengan data user yang sebenarnya
const token = 'exampleToken'; // Gantilah dengan token yang sebenarnya
sendTransactionalEmail(user, token)
		.then(result => {
				console.log('sendEmail', result);
		})
		.catch(error => {
				console.error('Error in sending email:', error);
		});

 */