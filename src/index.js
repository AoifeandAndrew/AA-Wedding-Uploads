export default {
  async fetch(request, env) {
    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
      });
    }

    // Only allow GET requests for presigned URLs
    if (request.method !== 'GET') {
      return new Response('Method Not Allowed', { 
        status: 405,
        headers: {
          'Access-Control-Allow-Origin': '*',
        }
      });
    }

    // Get filename from URL parameters
    const url = new URL(request.url);
    const filename = url.searchParams.get('filename');
    
    if (!filename) {
      return new Response('Missing filename parameter', { 
        status: 400,
        headers: {
          'Access-Control-Allow-Origin': '*',
        }
      });
    }

    try {
      // Read environment variables
      const accessKeyId = env.R2_ACCESS_KEY_ID || 'd70f16fb96e8b93d2530fffa162ac07c';
      const secretAccessKey = env.R2_SECRET_ACCESS_KEY || '52eb8165acc2b3a3bfcd13e295eed361b3877af537a0a2236fc1379065b2d5a9';
      const bucket = 'wedding-uploads';
      const endpoint = 'https://9e9500d1925c42f12f71e04cda1a1c98.r2.cloudflarestorage.com';

      const region = 'auto';
      const service = 's3';
      const now = new Date();
      const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
      const shortDate = amzDate.substring(0, 8);

      // Add timestamp to filename to avoid conflicts
      const timestamp = Date.now();
      const fileExtension = filename.split('.').pop();
      const baseName = filename.replace(/\.[^/.]+$/, '');
      const uniqueFilename = `${baseName}_${timestamp}.${fileExtension}`;

      const credentialScope = `${shortDate}/${region}/${service}/aws4_request`;
      const credential = `${accessKeyId}/${credentialScope}`;

      const host = new URL(endpoint).host;
      const urlPath = `/${uniqueFilename}`;

      const signedHeaders = 'host';
      const canonicalRequest = [
        'PUT',
        urlPath,
        '',
        `host:${host}`,
        '',
        signedHeaders,
        'UNSIGNED-PAYLOAD'
      ].join('\n');

      const stringToSign = [
        'AWS4-HMAC-SHA256',
        amzDate,
        credentialScope,
        await hashSHA256(canonicalRequest)
      ].join('\n');

      const signingKey = await getSigningKey(secretAccessKey, shortDate, region, service);
      const signature = await hmacSHA256Hex(signingKey, stringToSign);

      // Set expiration to 1 hour from now
      const expires = Math.floor(Date.now() / 1000) + 3600;

      const presignedURL = `${endpoint}${urlPath}?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=${encodeURIComponent(credential)}&X-Amz-Date=${amzDate}&X-Amz-Expires=3600&X-Amz-SignedHeaders=${signedHeaders}&X-Amz-Signature=${signature}`;

      return new Response(JSON.stringify({ 
        url: presignedURL,
        filename: uniqueFilename 
      }), {
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });

    } catch (error) {
      console.error('Error generating presigned URL:', error);
      return new Response(JSON.stringify({ 
        error: 'Failed to generate upload URL',
        details: error.message 
      }), {
        status: 500,
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }
  }
}

// Helper: SHA-256 hash
async function hashSHA256(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper: HMAC-SHA256
async function hmacSHA256Hex(key, message) {
  const encoder = new TextEncoder();
  const keyData = typeof key === 'string' ? encoder.encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper: AWS-style signing key
async function getSigningKey(secret, date, region, service) {
  const kDate = await hmacSHA256Raw(`AWS4${secret}`, date);
  const kRegion = await hmacSHA256Raw(kDate, region);
  const kService = await hmacSHA256Raw(kRegion, service);
  const kSigning = await hmacSHA256Raw(kService, 'aws4_request');
  return [...new Uint8Array(kSigning)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Raw binary HMAC helper
async function hmacSHA256Raw(key, message) {
  const encoder = new TextEncoder();
  const keyData = typeof key === 'string' ? encoder.encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message));
}