const axios = require('axios');

// Fungsi untuk memanggil webhook
async function callWebHook(client, req, eventType, eventData) {
	try {
		const webhookUrl = 'https://example.com/webhook'; // Gantilah dengan URL webhook Anda

		const payload = {
			eventType: eventType,
			eventData: eventData,
			session: client.session,
		};

		// Memanggil webhook dengan menggunakan axios atau library HTTP yang sesuai
		await axios.post(webhookUrl, payload);

		// Tambahkan log atau tindakan lain setelah berhasil memanggil webhook
		console.log(`Webhook called successfully for event type: ${eventType}`);
	} catch (error) {
		// Tangani kesalahan jika pemanggilan webhook gagal
		console.error('Failed to call webhook:', error.message);
	}
}

async function handleIncomingMessage(req, res) {
	const session = req.params.session;
	// const client = whatsappSession.getClient(session);
	const client = { session }; // Simulasikan objek client sesuai dengan kebutuhan Anda

	try {
		const { from, body } = req.body;

		// Logika atau pemrosesan pesan masuk
		// ...

		// Pemanggilan webhook
		callWebHook(client, req, 'incomingMessage', { from, body });

		res.status(200).json({ status: 'success', message: 'Message handled successfully' });
	} catch (error) {
		console.error(error);
		res.status(500).json({ status: 'error', message: 'Failed to handle incoming message' });
	}
};

async function scheduleMessage(req, res) {
	const session = req.params.session;
	const client = whatsappSession.getClient(session);

	try {
		const { to, message, scheduleTime } = req.body;

		// Logika untuk menjadwalkan pengiriman pesan
		// ...

		// Menjadwalkan pengiriman pesan
		const scheduledDate = new Date(scheduleTime);
		await client.sendText(to, message, { scheduledDate });

		res.status(200).json({ status: 'success', message: 'Message scheduled successfully' });
	} catch (error) {
		console.error(error);
		res.status(500).json({ status: 'error', message: 'Failed to schedule message' });
	}
};

module.exports = {
	callWebHook,
	handleIncomingMessage,
	scheduleMessage
};


// Aplikasi Penerima Webhook
const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const port = 3000; // Sesuaikan dengan port yang Anda inginkan

app.use(bodyParser.json());

// Endpoint untuk menerima webhook dari WhatsApp
app.post('/webhook', (req, res) => {
  const { eventType, eventData, session } = req.body;

  // Lakukan sesuatu dengan data yang diterima, misalnya, simpan ke basis data, kirim notifikasi, dll.
  console.log(`Received webhook for session ${session}, event type: ${eventType}, data:`, eventData);

  res.status(200).send('Webhook received successfully');
});

app.listen(port, () => {
  console.log(`Webhook server is running at http://localhost:${port}/webhook`);
});