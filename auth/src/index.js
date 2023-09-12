const Sentry = require("@sentry/node");
// or use es6 import statements
// import * as Sentry from '@sentry/node';

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
require('dotenv').config()

const jira = require('./jira/jira');
const auth = require('./auth/auth');

const app = express();

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  tracesSampleRate: 1.0,
});

// middleware
app.use(express.json());
app.use(cors({
	credentials: true,
	origin: true
}));
app.use(morgan('tiny'));
app.use(cookieParser());
app.disable('x-powered-by');

// routes
app.use('/auth', auth); 
app.use('/jira', jira); 

// error handler
app.use((err, req, res, next) => {
	if (err) {
		console.error(err.message);
		console.error(err.stack);
		return res.status(err.output.statusCode || 500).json(err.output.payload);
	}
});

const port = process.env.PORT || 3010;
app.listen(port, () => {
	console.log(`listening on port ${port}`);
});