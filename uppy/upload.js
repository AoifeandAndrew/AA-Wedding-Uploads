import React from 'https://esm.sh/react';
import { createRoot } from 'https://esm.sh/react-dom/client';
import { UppyReactComponent } from 'https://esm.sh/@uppy/react';
import Uppy from 'https://esm.sh/@uppy/core';
import XHRUpload from 'https://esm.sh/@uppy/xhr-upload';

const uppy = new Uppy({
  restrictions: { maxNumberOfFiles: 1 },
  autoProceed: true
}).use(XHRUpload, {
  endpoint: 'https://your-worker-url.dev/', // Will fetch presigned URL from here
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  getResponseData: (res) => res,
  getUploadParameters: async (file) => {
    const response = await fetch('https://your-worker-url.dev/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: file.name })
    });
    const { url } = await response.json();
    return {
      method: 'PUT',
      url,
      headers: { 'Content-Type': file.type }
    };
  }
});

function UploadPage() {
  return (
    <div>
      <h2>Upload a file</h2>
      <UppyReactComponent uppy={uppy} />
    </div>
  );
}

createRoot(document.getElementById('root')).render(<UploadPage />);
