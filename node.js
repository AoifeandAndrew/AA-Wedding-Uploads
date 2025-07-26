// sign.js
import crypto from 'crypto';
import { URL } from 'url';

function getSignedUrl({
  bucket,
  region = 'auto',
  accessKeyId,
  secretAccessKey,
  endpoint,
  key,
  expiresIn = 300, // 5 minutes
  contentType = 'image/jpeg',
}) {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.substring(0, 8);
  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
  const host = new URL(endpoint).host;

  const canonicalUri = `/${bucket}/${key}`;
  const canonicalHeaders = `host:${host}\nx-amz-acl:public-read\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-acl;x-amz-content-sha256;x-amz-date';
  const algorithm = 'AWS4-HMAC-SHA256';

  const queryParams = new URLSearchParams({
    'X-Amz-Algorithm': algorithm,
    'X-Amz-Credential': `${accessKeyId}/${credentialScope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': expiresIn.toString(),
    'X-Amz-SignedHeaders': signedHeaders,
  });

  const canonicalQuerystring = queryParams.toString();
  const canonicalRequest = [
    'PUT',
    canonicalUri,
    canonicalQuerystring,
    canonicalHeaders,
    signedHeaders,
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    crypto.createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');

  const kDate = crypto.createHmac('sha256', `AWS4${secretAccessKey}`).update(dateStamp).digest();
  const kRegion = crypto.createHmac('sha256', kDate).update(region).digest();
  const kService = crypto.createHmac('sha256', kRegion).update('s3').digest();
  const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();

  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');
  queryParams.set('X-Amz-Signature', signature);

  const uploadUrl = `${endpoint}/${bucket}/${key}?${queryParams.toString()}`;
  return uploadUrl;
}
