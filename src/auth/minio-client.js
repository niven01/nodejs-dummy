const Minio = require('minio');

const { MINIO_ACCESS_KEY, MINIO_SECRET_KEY } = require('../config');

const minioClient = new Minio.Client({
  endPoint: 'prd-cdn.enexo.io',
  port: 443,
  useSSL: true,
  accessKey: MINIO_ACCESS_KEY,
  secretKey: MINIO_SECRET_KEY
});

module.exports = minioClient
