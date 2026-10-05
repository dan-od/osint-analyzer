/** @type {import('next').NextConfig} */
const nextConfig = {
  eslint: {
    ignoreDuringBuilds: true,
  },
  experimental: {
    // Native / filesystem-reading modules stay as plain Node requires on the server
    serverComponentsExternalPackages: ['better-sqlite3', 'ip2proxy-nodejs'],
  },
};

export default nextConfig;
