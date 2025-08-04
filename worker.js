// Cloudflare Worker for R2 presigned URL generation only
// Expects environment variables: R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_ENDPOINT, R2_REGION, R2_BUCKET_NAME

const ALLOWED_EXTENSIONS = ["jpg", "jpeg", "png", "heic", "mp4"];

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request, event));
});

async function handleRequest(request, event) {
  const env = event?.env || globalThis;
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (request.method === "POST") {
    let data;
    try {
      data = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400, headers: corsHeaders });
    }
    const { filename } = data;
    if (!filename || typeof filename !== "string") {
      return new Response(JSON.stringify({ error: "Missing or invalid filename" }), { status: 400, headers: corsHeaders });
    }
    const extension = filename.split(".").pop().toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(extension)) {
      return new Response(JSON.stringify({ error: "Invalid file type. Allowed: JPEG, PNG, HEIC, MP4" }), { status: 400, headers: corsHeaders });
    }
    const uniqueName = `${Date.now()}-${Math.random().toString(36).slice(2)}-${filename}`;

    // Determine content-type based on extension
    let contentType = "application/octet-stream";
    if (extension === "jpg" || extension === "jpeg") contentType = "image/jpeg";
    else if (extension === "png") contentType = "image/png";
    else if (extension === "heic") contentType = "image/heic";
    else if (extension === "mp4") contentType = "video/mp4";

    let url;
    try {
      url = await generatePresignedUrl(env, uniqueName, contentType);
    } catch (err) {
      return new Response(JSON.stringify({ error: "Failed to generate presigned URL" }), { status: 500, headers: corsHeaders });
    }
    return new Response(JSON.stringify({ url, contentType }), { status: 200, headers: corsHeaders });
  }

  return new Response(JSON.stringify({ error: "Method Not Allowed" }), { status: 405, headers: corsHeaders });
}

// AWS Signature V4 for R2 PUT
async function generatePresignedUrl(env, key, contentType) {
  const encoder = new TextEncoder();
  function toHex(buffer) {
    return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, "0")).join("");
  }
  async function sha256(message) {
    return crypto.subtle.digest("SHA-256", encoder.encode(message));
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

  const method = "PUT";
  const host = new URL(env.R2_ENDPOINT).host;
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${env.R2_REGION}/s3/aws4_request`;
  const algorithm = "AWS4-HMAC-SHA256";
  const signedHeaders = "host;content-type";
  const canonicalUri = `/${env.R2_BUCKET_NAME}/${key}`;
  const canonicalQuery = [
    `X-Amz-Algorithm=${algorithm}`,
    `X-Amz-Credential=${encodeURIComponent(`${env.R2_ACCESS_KEY_ID}/${credentialScope}`)}`,
    `X-Amz-Date=${amzDate}`,
    `X-Amz-Expires=900`,
    `X-Amz-SignedHeaders=${signedHeaders}`
  ].join("&");
  const canonicalHeaders = `host:${host}\ncontent-type:${contentType}\n`;
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
