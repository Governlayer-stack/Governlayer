/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: '/api',
        destination: 'https://api-docs-iota-liart.vercel.app/',
      },
      {
        source: '/api/:path*',
        destination: 'https://api-docs-iota-liart.vercel.app/:path*',
      },
    ]
  },
}

module.exports = nextConfig
