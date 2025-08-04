// Cloudflare Worker for S3-compatible presigned URL generation (Backblaze B2, AWS S3, etc.)
// DUMB DUMB MODE: This file is for generating presigned URLs for browser uploads to S3-compatible storage.
// DO NOT use for direct file storage or for server-to-server flows that require extra signed headers.
//
// ENVIRONMENT VARIABLES REQUIRED (set in wrangler.toml and as secrets):
//   R2_ACCESS_KEY_ID:     Your B2 restricted key ID (NOT the master key)
//   R2_SECRET_ACCESS_KEY: Your B2 restricted application key
//   R2_ENDPOINT:          Your B2 S3 endpoint (e.g. https://s3.eu-central-003.backblazeb2.com)
//   R2_REGION:            Your B2 region (e.g. eu-central-003)
//   R2_BUCKET_NAME:       Your B2 bucket name (e.g. wedding-uploads)
//
// This Worker is designed to be called from your frontend to get a presigned URL for uploading a file.
// The browser then uploads directly to B2 using the presigned URL.
//
// This code signs ONLY the 'host' header for maximum browser compatibility. DO NOT add 'content-type' to signed headers!
//
// Supported file types: jpg, jpeg, png, heic, mp4 (see ALLOWED_EXTENSIONS)

const ALLOWED_EXTENSIONS = ["jpg", "jpeg", "png", "heic", "mp4"];

// This is the entry point for all HTTP requests to the Worker
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request, event));
});

// Main handler for all requests
async function handleRequest(request, event) {
  // Get environment variables (from wrangler.toml and secrets)
  const env = event?.env || globalThis;
  // Set CORS headers so browsers can call this Worker from any origin (adjust as needed)
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };

  // Handle CORS preflight requests (OPTIONS)
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // Only allow POST requests for presigned URL generation
  if (request.method === "POST") {
    let data;
    try {
      data = await request.json();
    } catch {
      // If the request body is not valid JSON, return an error
      return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400, headers: corsHeaders });
    }
    const { filename } = data;
    if (!filename || typeof filename !== "string") {
      // If no filename is provided, return an error
      return new Response(JSON.stringify({ error: "Missing or invalid filename" }), { status: 400, headers: corsHeaders });
    }
    // Only allow certain file extensions
    const extension = filename.split(".").pop().toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(extension)) {
      return new Response(JSON.stringify({ error: "Invalid file type. Allowed: JPEG, PNG, HEIC, MP4" }), { status: 400, headers: corsHeaders });
    }
    // Generate a unique name for the file to avoid collisions
    const uniqueName = `${Date.now()}-${Math.random().toString(36).slice(2)}-${filename}`;

    let url;
    try {
      // Generate the presigned URL for uploading
      url = await generatePresignedUrl(env, uniqueName);
    } catch (err) {
      // If something goes wrong, return a 500 error
      return new Response(JSON.stringify({ error: "Failed to generate presigned URL" }), { status: 500, headers: corsHeaders });
    }
    // Return the presigned URL to the frontend
    return new Response(JSON.stringify({ url }), { status: 200, headers: corsHeaders });
  }

  // If the method is not POST or OPTIONS, return 405
  return new Response(JSON.stringify({ error: "Method Not Allowed" }), { status: 405, headers: corsHeaders });
}

// This function generates a presigned URL for uploading a file to S3-compatible storage
// It signs ONLY the 'host' header for browser compatibility (do NOT add content-type here)
async function generatePresignedUrl(env, key) {
  // DUMB DUMB: Don't touch this unless you know AWS Signature V4 inside out!
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

  // These are the only things you should ever need to change for a different S3-compatible provider:
  const method = "PUT"; // Always PUT for uploads
  const host = new URL(env.R2_ENDPOINT).host; // S3 endpoint host
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, ""); // e.g. 20240728T123456Z
  const dateStamp = amzDate.slice(0, 8); // e.g. 20240728
  const credentialScope = `${dateStamp}/${env.R2_REGION}/s3/aws4_request`;
  const algorithm = "AWS4-HMAC-SHA256";
  const signedHeaders = "host"; // DO NOT add content-type here for browser uploads!
  const canonicalUri = `/${env.R2_BUCKET_NAME}/${key}`;
  const canonicalQuery = [
    `X-Amz-Algorithm=${algorithm}`,
    `X-Amz-Credential=${encodeURIComponent(`${env.R2_ACCESS_KEY_ID}/${credentialScope}`)}`,
    `X-Amz-Date=${amzDate}`,
    `X-Amz-Expires=900`, // 15 minutes
    `X-Amz-SignedHeaders=${signedHeaders}`
  ].join("&");
  const canonicalHeaders = `host:${host}\n`;
  const payloadHash = "UNSIGNED-PAYLOAD"; // Don't sign the file content for browser uploads
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
  // The next four lines are the AWS Signature V4 key derivation steps (do not change)
  const kDate = await hmac(`AWS4${env.R2_SECRET_ACCESS_KEY}`, dateStamp);
  const kRegion = await hmac(kDate, env.R2_REGION);
  const kService = await hmac(kRegion, "s3");
  const kSigning = await hmac(kService, "aws4_request");
  const signature = toHex(await hmac(kSigning, stringToSign));
  // This is the final presigned URL you return to the browser
  return `${env.R2_ENDPOINT}/${env.R2_BUCKET_NAME}/${key}?${canonicalQuery}&X-Amz-Signature=${signature}`;
}
