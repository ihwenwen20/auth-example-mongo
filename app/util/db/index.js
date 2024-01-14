const { urlDb } = require('../../config');
const mongoose = require('mongoose');
mongoose.set("strictQuery", false);

// mongoose.connect(urlDb, options = { useNewUrlParser: true, useUnifiedTopology: true }).then(() => {
	// mongoose.connect(urlDb).then(() => {
	// 	console.log("Successfully connect to MongoDB.");
	// }).catch(err => {
	// 	console.error("Connection error", err);
	// 	process.exit();
	// });

const connectToDatabase = async () => {
	try {
		await mongoose.connect(urlDb);
		console.log("Successfully connect to MongoDB.");
	} catch (err) {
		console.error("Connection error", err);
		process.exit();
	}
};

connectToDatabase();

const db = mongoose.connection;

module.exports = db;