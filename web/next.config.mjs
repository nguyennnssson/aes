/** @type {import('next').NextConfig} */
// In live mode, /api/* is proxied to the FastAPI backend (dashboard/app.py) so the
// browser talks to one origin and avoids CORS. Override with AES_API_ORIGIN if the
// backend runs elsewhere. In demo mode the app uses bundled sample data and never
// hits these routes.
const API_ORIGIN = process.env.AES_API_ORIGIN || "http://127.0.0.1:8000";

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API_ORIGIN}/api/:path*` }];
  },
};

export default nextConfig;
