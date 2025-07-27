import React from 'https://esm.sh/react';
import { createRoot } from 'https://esm.sh/react-dom/client';
import { Dashboard } from 'https://esm.sh/@uppy/react';
import Uppy from 'https://esm.sh/@uppy/core';
import XHRUpload from 'https://esm.sh/@uppy/xhr-upload';

const uppy = new Uppy({
  restrictions: { maxNumberOfFiles: 1 },
  autoProceed: true
}).use(XHRUpload, {
  endpoint: 'https://uploader-fix.andrewandaoifegethitched.workers.dev/', // ← Change this to your Worker URL
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  getResponseData: res => res,
  getUploadParameters: async (file) => {
    const res = await fetch('https://uploader-fix.andrewandaoifegethitched.workers.dev/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: file.name })
    });
    const { url } = await res.json();
    return {
      method: 'PUT',
      url,
      headers: { 'Content-Type': file.type }
    };
  }
});

function UploadPage() {
  return React.createElement(
    "div",
    null,
    React.createElement("h2", null, "Share a memory from the celebration 💫"),
    React.createElement(Dashboard, { uppy })
  );
}

createRoot(document.getElementById("root")).render(React.createElement(UploadPage));
