const dns = require('dns').promises;
const tls = require('tls');
const https = require('https');
const http = require('http');
const { URL } = require('url');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  const { target } = JSON.parse(req.body);
  if (!target) return res.status(400).json({ error: 'Target URL is required' });

  let url;
  try {
    url = new URL(target.startsWith('http') ? target : `https://${target}`);
  } catch (e) {
    return res.json({ error: 'Invalid URL format' });
  }

  // Security: Block private IPs
  const privateIPRegex = /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|::1|fe80)/;
  if (privateIPRegex.test(url.hostname)) {
    return res.json({ error: 'Internal/Private targets are not allowed' });
  }

  const results = {
    timestamp: Date.now(),
    target: url.href,
    domain: url.hostname,
    dns: {},
    tls: null,
    headers: {},
    security: [],
    tech: [],
    files: {},
    score: 100
  };

  try {
    // 1. DNS Lookup
    const addresses = await dns.resolve4(url.hostname).catch(() => []);
    results.dns.ip = addresses[0] || 'Unknown';
    if (addresses[0]) {
      results.dns.reverse = await dns.reverse(addresses[0]).catch(() => ['None']);
    }

    // 2. TLS Info (on port 443)
    const tlsPromise = new Promise((resolve) => {
      const socket = tls.connect(443, url.hostname, { servername: url.hostname, timeout: 3000 }, () => {
        const cert = socket.getPeerCertificate();
        resolve({
          protocol: socket.getProtocol(),
          authorized: socket.authorized,
          issuer: cert.issuer?.O || 'Unknown',
          valid_to: cert.valid_to
        });
        socket.destroy();
      });
      socket.on('error', () => resolve(null));
      socket.setTimeout(3000, () => { socket.destroy(); resolve(null); });
    });
    results.tls = await tlsPromise;

    // 3. HTTP Headers & HTML Analysis
    const fetchTarget = async (protocol) => {
        return new Promise((resolve) => {
            const client = protocol === 'https:' ? https : http;
            client.get(url.href, { timeout: 5000, headers: { 'User-Agent': 'ReconShield/1.0 (Passive Audit)' } }, (res) => {
                let data = '';
                res.on('data', d => { if (data.length < 50000) data += d; });
                res.on('end', () => resolve({ headers: res.headers, body: data }));
            }).on('error', () => resolve(null));
        });
    };

    const scanData = await fetchTarget(url.protocol);
    if (scanData) {
        results.headers = scanData.headers;
        const h = scanData.headers;
        
        // Security Headers Check
        const secHeaders = {
            'Strict-Transport-Security': 'HSTS non détecté',
            'Content-Security-Policy': 'CSP absente',
            'X-Frame-Options': 'Protection Clickjacking absente',
            'X-Content-Type-Options': 'MIME Sniffing non protégé',
            'Referrer-Policy': 'Referrer-Policy non configurée'
        };

        for (const [key, msg] of Object.entries(secHeaders)) {
            if (!h[key.toLowerCase()]) {
                results.security.push({ level: 'moyen', msg });
                results.score -= 10;
            }
        }

        // Tech Detection (Simple Signatures)
        const body = scanData.body.toLowerCase();
        if (h['server']) results.tech.push(`Serveur: ${h['server']}`);
        if (h['x-powered-by']) results.tech.push(`Powered by: ${h['x-powered-by']}`);
        if (body.includes('wp-content')) results.tech.push('WordPress CMS');
        if (body.includes('_next/static')) results.tech.push('Next.js Framework');
        if (body.includes('react.')) results.tech.push('React Library');
        if (body.includes('nuxt')) results.tech.push('Nuxt.js');
    }

    // 4. Standard Files Check (Basic HEAD requests)
    const checkFile = async (path) => {
        return new Promise(r => {
            const req = https.request(`https://${url.hostname}${path}`, { method: 'HEAD', timeout: 2000 }, (res) => r(res.statusCode === 200));
            req.on('error', () => r(false));
            req.end();
        });
    };
    results.files.robots = await checkFile('/robots.txt');
    results.files.security = await checkFile('/.well-known/security.txt');
    results.files.sitemap = await checkFile('/sitemap.xml');

    results.score = Math.max(0, results.score);
    res.status(200).json(results);

  } catch (err) {
    res.status(200).json({ error: 'Scan failed: ' + err.message });
  }
};
