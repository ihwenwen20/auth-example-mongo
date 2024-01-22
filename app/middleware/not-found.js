const notFound = (req, res) => {
	res.status(404).send({statusCode: 404, message: 'Route does not exist.'});
};

module.exports = notFound;