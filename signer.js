// signer.js
const encoder = new TextEncoder();

async function sha256(message) {
  const data = encoder.encode(message);
  return crypto.subtle.digest("SHA-256", data);
}

async function hmac(key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    typeof key === "string" ? encoder.encode(key) : key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(message));
}

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function generateSignedUrl(env, key) {
  const method = "PUT";
  const host = new URL(env.R2_ENDPOINT).host;
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${env.R2_REGION}/s3/aws4_request`;
  const algorithm = "AWS4-HMAC-SHA256";
  const signedHeaders = "host";

  const canonicalUri = `/${env.R2_BUCKET_NAME}/${key}`;
  const canonicalQuery = [
    `X-Amz-Algorithm=${algorithm}`,
    `X-Amz-Credential=${encodeURIComponent(`${env.R2_ACCESS_KEY_ID}/${credentialScope}`)}`,
    `X-Amz-Date=${amzDate}`,
    `X-Amz-Expires=900`,
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

  const hashedRequest = await sha256(canonicalRequest);
  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    toHex(hashedRequest)
  ].join("\n");

  const kDate = await hmac(`AWS4${env.R2_SECRET_ACCESS_KEY}`, dateStamp);
  const kRegion = await hmac(kDate, env.R2_REGION);
  const kService = await hmac(kRegion, "s3");
  const kSigning = await hmac(kService, "aws4_request");
  const signature = toHex(await hmac(kSigning, stringToSign));

  return `${env.R2_ENDPOINT}/${env.R2_BUCKET_NAME}/${key}?${canonicalQuery}&X-Amz-Signature=${signature}`;
}
