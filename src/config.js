require('dotenv').config()

exports.USER_FIELDS = process.env.USER_FIELDS ? process.env.USER_FIELDS.split(',') : [];
exports.USER_MANAGEMENT_DATABASE_SCHEMA_NAME = process.env.USER_MANAGEMENT_DATABASE_SCHEMA_NAME || 'public';
exports.USER_REGISTRATION_AUTO_ACTIVE = true;
exports.HASURA_GRAPHQL_JWT_SECRET = JSON.parse(process.env.HASURA_GRAPHQL_JWT_SECRET)
exports.REFRESH_TOKEN_EXPIRES = process.env.REFRESH_TOKEN_EXPIRES || (60 * 24 * 30); // expire after 30 days
exports.JWT_TOKEN_EXPIRES = process.env.JWT_TOKEN_EXPIRES || 15; // expire after 15 m
exports.TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID
exports.TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN
exports.EMAIL_USER = process.env.EMAIL_USER
exports.EMAIL_DOMAIN = process.env.EMAIL_DOMAIN
exports.EMAIL_PASSWORD = process.env.EMAIL_PASSWORD
exports.MAILGUN_AUTH = process.env.MAILGUN_AUTH
exports.HASURA_SECRET = process.env.HASURA_SECRET
exports.HASURA_ENDPOINT = process.env.HASURA_ENDPOINT
exports.MINIO_ACCESS_KEY = process.env.MINIO_ACCESS_KEY
exports.MINIO_SECRET_KEY = process.env.MINIO_SECRET_KEY
exports.HASURA_ENEXO_ENDPOINT = process.env.HASURA_ENEXO_ENDPOINT
exports.HASURA_ENEXO_SECRET = process.env.HASURA_ENEXO_SECRET
exports.HASURA_FIELDFUSION_ENDPOINT = process.env.HASURA_FIELDFUSION_ENDPOINT
exports.HASURA_FIELDFUSION_SECRET = process.env.HASURA_FIELDFUSION_SECRET
exports.JIRA_USERNAME = process.env.JIRA_USERNAME
exports.JIRA_API_PASSWORD = process.env.JIRA_API_PASSWORD
exports.AUTH_DOMAIN = process.env.AUTH_DOMAIN