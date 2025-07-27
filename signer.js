// signer.js

const encoder = new TextEncoder();

export function getSignedUrl({ accessKey, secretKey, bucket, region, endpoint, key, expiresInSeconds }) {
  const service = "s3";
  const method = "PUT";
  const host = new URL(endpoint).host;
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const shortDate = amzDate.slice(0, 8);
  const credentialScope = `${shortDate}/${region}/${service}/aws4_request`;
  const algorithm = "AWS4-HMAC-SHA256";
  const expires = expiresInSeconds.toString();
  const signedHeaders = "host";

  // Create canonical request
  const canonicalUri = `/${bucket}/${key}`;
  const canonicalQuery = [
    `X-Amz-Algorithm=${algorithm}`,
    `X-Amz-Credential=${encodeURIComponent(`${accessKey}/${credentialScope}`)}`,
    `X-Amz-Date=${amzDate}`,
    `X-Amz-Expires=${expires}`,
    `X-Amz-SignedHeaders=${signedHeaders}`
  ].join("&");

  const canonicalHeaders = `host:${host}\n`;
  const payloadHash = "UNSIGNED-PAYLOAD";

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join("\n");

  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    toHex(sha256(canonicalRequest))
  ].join("\n");

  // Generate signing key
  const kDate = hmac(`AWS4${secretKey}`, shortDate);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, "aws4_request");

  const signature = toHex(hmac(kSigning, stringToSign));

  const signedUrl = `${endpoint}/${bucket}/${key}?${canonicalQuery}&X-Amz-Signature=${signature}`;
  return signedUrl;
}

// WebCrypto helpers
function sha256(str) {
  return crypto.subtle.digest("SHA-256", encoder.encode(str));
}

async function hmac(key, data) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    typeof key === "string" ? encoder.encode(key) : key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(data));
}

function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}
