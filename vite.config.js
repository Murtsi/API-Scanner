import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Helmet-style CSP and security headers for dev/preview (production: set at server/proxy)
const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://your-railway-backend.up.railway.app; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self';";

export default defineConfig({
  plugins: [react()],
  server: {
    headers: {
      'Content-Security-Policy': csp,
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=()'
    }
  },
  preview: {
    headers: {
      'Content-Security-Policy': csp,
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=()'
    }
  }
});
