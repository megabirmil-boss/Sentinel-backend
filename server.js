const express = require('express');
const cors = require('cors');
const axios = require('axios');
const admin = require('firebase-admin');
const cron = require('node-cron');
// require('dotenv').config(); // Render uses environment variables instead

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Firebase for push notifications
admin.initializeApp({
  credential: admin.credential.cert(process.env.FIREBASE_KEY || {
    type: "service_account",
    project_id: "sentinel-security",
    private_key: "your-firebase-key",
    client_email: "firebase@sentinel.iam.gserviceaccount.com"
  })
});

// Database (use MongoDB, PostgreSQL, or Firebase in production)
const threats = {};
const users = {};
const breaches = {};

// THREAT DETECTION APIs
const URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/urls/recent/';
const VIRUSTOTAL_API = 'https://www.virustotal.com/api/v3/urls';
const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_KEY || 'your-api-key';
const HIBP_API = 'https://haveibeenpwned.com/api/v3/breachedaccount/';

// ========== THREAT DETECTION ==========

// Get latest malicious URLs
async function fetchMaliciousURLs() {
  try {
    const response = await axios.get(URLHAUS_API, { timeout: 5000 });
    return response.data.urls || [];
  } catch (error) {
    console.log('URLhaus API error:', error.message);
    return [];
  }
}

// Check if URL is malicious
async function checkURL(url) {
  try {
    const response = await axios.post(
      `${VIRUSTOTAL_API}/lookup`,
      { url },
      { headers: { 'x-apikey': VIRUSTOTAL_KEY }, timeout: 5000 }
    );

    const stats = response.data.data.attributes.last_analysis_stats;
    const malicious = stats.malicious || 0;

    return {
      url,
      malicious: malicious > 0,
      score: malicious,
      timestamp: new Date()
    };
  } catch (error) {
    console.log('VirusTotal check failed');
    return null;
  }
}

// Scan for phishing patterns
function detectPhishing(content) {
  const phishingPatterns = [
    /verify.*account/i,
    /confirm.*password/i,
    /update.*payment/i,
    /urgent.*action/i,
    /click.*immediately/i,
    /suspended.*account/i,
    /confirm.*identity/i
  ];

  return phishingPatterns.some(pattern => pattern.test(content));
}

// ========== BREACH MONITORING ==========

// Check email against Have I Been Pwned
async function checkEmailBreach(email) {
  try {
    const response = await axios.get(
      `${HIBP_API}${encodeURIComponent(email)}`,
      {
        headers: { 'User-Agent': 'Sentinel-Security' },
        timeout: 5000
      }
    );

    if (response.status === 200) {
      return {
        email,
        breaches: response.data.map(b => ({
          name: b.Name,
          date: b.BreachDate,
          count: b.PwnCount
        })),
        found: true
      };
    }
  } catch (error) {
    if (error.response?.status === 404) {
      return { email, breaches: [], found: false };
    }
    console.log('HIBP check error');
  }
  return null;
}

// ========== PUSH NOTIFICATIONS ==========

// Send push notification
async function sendPushNotification(userId, title, message, data = {}) {
  try {
    const tokens = users[userId]?.fcmTokens || [];
    
    if (tokens.length === 0) return;

    const payload = {
      notification: {
        title,
        body: message
      },
      data,
      webpush: {
        fcmOptions: { link: '/' }
      }
    };

    const response = await admin.messaging().sendMulticast({
      tokens,
      ...payload
    });

    console.log(`Sent to ${response.successCount} devices`);
    return response;
  } catch (error) {
    console.error('Push notification error:', error.message);
  }
}

// ========== MIDDLEWARE ==========

// API Key validation middleware
const API_KEY = process.env.SENTINEL_API_KEY || 'sentinel-secret-key-change-this';

app.use((req, res, next) => {
  // Allow health check without auth
  if (req.path === '/api/health') {
    return next();
  }

  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  next();
});

// ========== API ENDPOINTS ==========

// Register device for push notifications
app.post('/api/register-device', (req, res) => {
  const { userId, fcmToken } = req.body;

  if (!users[userId]) {
    users[userId] = { fcmTokens: [] };
  }

  if (!users[userId].fcmTokens.includes(fcmToken)) {
    users[userId].fcmTokens.push(fcmToken);
  }

  res.json({ success: true, message: 'Device registered' });
});

// Scan for threats
app.post('/api/scan', async (req, res) => {
  const { userId, urls = [] } = req.body;

  const results = [];

  for (const url of urls) {
    const threat = await checkURL(url);
    if (threat && threat.malicious) {
      results.push(threat);

      // Send notification
      await sendPushNotification(
        userId,
        'Threat Detected',
        `Malicious URL blocked: ${url}`,
        { type: 'threat', url }
      );
    }
  }

  if (!threats[userId]) threats[userId] = [];
  threats[userId].push(...results);

  res.json({ threats: results, total: results.length });
});

// Check email breaches
app.post('/api/check-breaches', async (req, res) => {
  const { userId, emails = [] } = req.body;

  const results = [];

  for (const email of emails) {
    const breach = await checkEmailBreach(email);

    if (breach && breach.found && breach.breaches.length > 0) {
      results.push(breach);

      // Send notification
      await sendPushNotification(
        userId,
        'Breach Found',
        `${email} found in ${breach.breaches.length} breach(es)`,
        { type: 'breach', email, count: breach.breaches.length }
      );
    }
  }

  if (!breaches[userId]) breaches[userId] = [];
  breaches[userId].push(...results);

  res.json({ breaches: results, total: results.length });
});

// Get user threats
app.get('/api/threats/:userId', (req, res) => {
  const { userId } = req.params;
  const userThreats = threats[userId] || [];

  res.json({
    threats: userThreats.slice(-50),
    count: userThreats.length,
    lastCheck: userThreats[userThreats.length - 1]?.timestamp || null
  });
});

// Get user breaches
app.get('/api/breaches/:userId', (req, res) => {
  const { userId } = req.params;
  const userBreaches = breaches[userId] || [];

  res.json({
    breaches: userBreaches,
    count: userBreaches.length,
    lastCheck: userBreaches[userBreaches.length - 1]?.timestamp || null
  });
});

// Manual full scan
app.post('/api/full-scan', async (req, res) => {
  const { userId } = req.body;

  // Get latest malicious URLs
  const urls = await fetchMaliciousURLs();

  const results = [];
  for (const urlData of urls.slice(0, 10)) {
    const threat = await checkURL(urlData.url);
    if (threat && threat.malicious) {
      results.push(threat);
    }
  }

  if (results.length > 0) {
    await sendPushNotification(
      userId,
      'Full Scan Complete',
      `Found ${results.length} threat(s)`,
      { type: 'scan', count: results.length }
    );
  }

  res.json({ threats: results, scanned: urls.length });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// ========== BACKGROUND JOBS ==========

// Scan for threats every hour
cron.schedule('0 * * * *', async () => {
  console.log('Running hourly threat scan...');

  for (const userId in users) {
    try {
      const urls = await fetchMaliciousURLs();

      for (const urlData of urls.slice(0, 5)) {
        const threat = await checkURL(urlData.url);
        if (threat && threat.malicious) {
          if (!threats[userId]) threats[userId] = [];
          threats[userId].push(threat);

          await sendPushNotification(
            userId,
            'New Threat Detected',
            `Malicious URL: ${urlData.url.substring(0, 30)}...`,
            { type: 'threat_auto' }
          );
        }
      }
    } catch (error) {
      console.log('Hourly scan error:', error.message);
    }
  }
});

// Check breaches every 12 hours
cron.schedule('0 */12 * * *', async () => {
  console.log('Running breach checks...');

  for (const userId in users) {
    try {
      // In production, get emails from database
      const userEmails = users[userId]?.emails || [];

      for (const email of userEmails) {
        const breach = await checkEmailBreach(email);

        if (breach && breach.found && breach.breaches.length > 0) {
          if (!breaches[userId]) breaches[userId] = [];
          breaches[userId].push(breach);

          await sendPushNotification(
            userId,
            'New Breach Alert',
            `${email} found in breach`,
            { type: 'breach_auto', email }
          );
        }
      }
    } catch (error) {
      console.log('Breach check error:', error.message);
    }
  }
});

// ========== SERVER ==========

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Sentinel backend running on port ${PORT}`);
  console.log('Threat detection active');
  console.log('Background jobs scheduled');
});
