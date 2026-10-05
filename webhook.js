const express = require('express');
const crypto = require('crypto');
const app = express();

// Middleware to parse form-encoded data (GitHub sends it this way)
app.use(express.urlencoded({ extended: true }));

// Your webhook secret from GitHub settings
const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;

// Verify GitHub signature
function verifySignature(req, secret) {
  if (!secret) {
    console.warn('No webhook secret configured. Signature verification skipped.');
    return true;
  }

  const signature = req.headers['x-hub-signature-256'];
  if (!signature) return false;

  const body = req.rawBody || JSON.stringify(req.body);
  const hash = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(body)
    .digest('hex');

  return crypto.timingSafeEqual(signature, hash);
}

// Store raw body for signature verification
app.use((req, res, next) => {
  let data = '';
  req.on('data', chunk => data += chunk);
  req.on('end', () => {
    req.rawBody = data;
    next();
  });
});

// Webhook endpoint
app.post('/webhook', (req, res) => {
  const event = req.headers['x-github-event'];
  const delivery = req.headers['x-github-delivery'];

  console.log(`[${delivery}] Received event: ${event}`);

  // Verify signature
  if (!verifySignature(req, WEBHOOK_SECRET)) {
    console.error('Signature verification failed');
    return res.status(403).json({ error: 'Signature mismatch' });
  }

  // Parse the payload (it comes as form data)
  let payload;
  try {
    if (req.body.payload) {
      payload = JSON.parse(req.body.payload);
    } else {
      payload = req.body;
    }
  } catch (err) {
    console.error('Failed to parse payload:', err);
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  // Handle ping event (webhook verification)
  if (event === 'ping') {
    console.log('Ping received. Webhook is working.');
    return res.status(200).json({ ok: true, message: 'Webhook verified' });
  }

  // Handle push event
  if (event === 'push') {
    const repo = payload.repository.full_name;
    const branch = payload.ref.split('/').pop(); // main, dev, etc
    const commits = payload.commits || [];
    const pusher = payload.pusher.name;

    console.log(`\n=== PUSH EVENT ===`);
    console.log(`Repo: ${repo}`);
    console.log(`Branch: ${branch}`);
    console.log(`Pusher: ${pusher}`);
    console.log(`Commits: ${commits.length}`);

    commits.forEach((commit, i) => {
      console.log(`  [${i + 1}] ${commit.message.split('\n')[0]}`);
      console.log(`      SHA: ${commit.id.slice(0, 7)}`);
      console.log(`      Files: ${commit.modified.length} modified, ${commit.added.length} added, ${commit.removed.length} removed`);
    });

    // YOUR LOGIC HERE
    // Examples:
    // - Trigger a CI/CD pipeline (Jenkins, GitHub Actions, etc)
    // - Send a Slack notification
    // - Deploy to production
    // - Run security scans
    // - Sync data to a database
    // - Send to a backend service

    // For now, just log it
    console.log('Processing complete.\n');
    return res.status(200).json({ ok: true, processed: commits.length });
  }

  // Ignore other events
  console.log(`Event type '${event}' not handled.`);
  res.status(200).json({ ok: true, ignored: true });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Webhook server listening on port ${PORT}`);
  console.log(`POST /webhook - GitHub webhook endpoint`);
});
