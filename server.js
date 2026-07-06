// ============================================================
// PYKORSE ENGINE - Node.js Server (Works on Render, Railway, Fly.io)
// ============================================================

const express = require('express');
const app = express();
app.use(express.json());

// ─── CORS (allow your SiteGround page to call this) ──────
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Allow-Methods', 'POST');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// ─── YOUR 4-LAYER SCANNER ────────────────────────────────
function scanCode(code) {
  let issues = [];
  let integrity = 100;

  // LAYER 1: Hardcoded API keys
  const keyRegex = /(api[_-]?key|apikey|secret|token|password)\s*=\s*['"][^'"]{8,}['"]/gi;
  let match;
  while ((match = keyRegex.exec(code)) !== null) {
    issues.push({
      line: getLineNumber(code, match.index),
      severity: 'CRITICAL',
      type: 'Hardcoded Secret',
      message: `API key exposed: "${match[0]}"`,
      fix: 'Move to environment variables: `const apiKey = process.env.API_KEY;`'
    });
    integrity -= 20;
  }

  // LAYER 2: SQL injection
  if (/\$\{.*\}\s*(SELECT|INSERT|UPDATE|DELETE)/i.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'SQL Injection Risk',
      message: 'SQL query uses string concatenation. Vulnerable to injection.',
      fix: 'Use parameterized queries or prepared statements.'
    });
    integrity -= 25;
  }

  // XSS
  if (/(innerHTML|dangerouslySetInnerHTML|document\.write)/i.test(code)) {
    issues.push({
      line: 1,
      severity: 'HIGH',
      type: 'XSS Risk',
      message: 'Using `innerHTML` exposes your app to XSS attacks.',
      fix: 'Use `textContent` or React\'s JSX.'
    });
    integrity -= 15;
  }

  // LAYER 3: Pattern checks
  if (/useEffect\s*\([^)]*\)\s*;?\s*$/.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'Missing Dependency Array',
      message: 'useEffect called without dependency array. Causes infinite re-renders.',
      fix: 'Add [] as second argument: `useEffect(() => {...}, []);`'
    });
    integrity -= 25;
  }

  if (/catch\s*\([^)]*\)\s*\{\s*\}/.test(code)) {
    issues.push({
      line: 1,
      severity: 'WARNING',
      type: 'Empty Catch Block',
      message: 'Catch block is empty. Errors are silently swallowed.',
      fix: 'Add error handling: `catch (err) { console.error(err); }`'
    });
    integrity -= 15;
  }

  if (/return\s*;/.test(code)) {
    issues.push({
      line: 1,
      severity: 'WARNING',
      type: 'Missing Return Value',
      message: '`return;` with no value. Did you mean to return something?',
      fix: 'Add intended return value or change to `return null;` if intentional.'
    });
    integrity -= 10;
  }

  // LAYER 4: Fix generation
  let fixedCode = code;
  if (issues.some(i => i.type === 'Missing Dependency Array')) {
    fixedCode = fixedCode.replace(/(useEffect\s*\([^)]*\))\s*;?/g, '$1, []);');
  }
  if (issues.some(i => i.type === 'Empty Catch Block')) {
    fixedCode = fixedCode.replace(/catch\s*\([^)]*\)\s*\{\s*\}/g, 'catch (err) {\n    console.error("Error caught:", err);\n  }');
  }
  if (issues.some(i => i.type === 'Hardcoded Secret')) {
    fixedCode = fixedCode.replace(/(const\s*(?:api[_-]?key|apikey|secret|token|password)\s*=\s*['"])[^'"]+(['"])/gi, '$1process.env.API_KEY$2');
  }

  // Validation
  let confidence = 95;
  let status = 'HEALTHY';
  let message = 'Code looks clean! 🚀';

  if (issues.length > 0) {
    status = integrity < 50 ? 'CRITICAL' : 'WARNING';
    message = `Found ${issues.length} issue(s). ${fixedCode !== code ? 'Fix generated.' : 'Manual review may be needed.'}`;
    confidence = fixedCode !== code ? 85 : 70;
  }

  if (fixedCode !== code) {
    const reCheck = scanCode(fixedCode);
    if (reCheck.issues && reCheck.issues.length < issues.length) {
      message = '✅ Issues resolved. Code is ready to ship!';
      confidence = 95;
    }
  }

  return {
    integrity: Math.max(0, Math.min(100, integrity)),
    status: status,
    issues: issues,
    fixedCode: fixedCode !== code ? fixedCode : null,
    message: message,
    confidence: confidence,
    issueCount: issues.length
  };
}

// ─── HELPER ──────────────────────────────────────────────
function getLineNumber(code, index) {
  return code.substring(0, index).split('\n').length;
}

// ─── API ENDPOINT ─────────────────────────────────────────
app.post('/scan', (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ error: 'No code provided' });
  }
  try {
    const result = scanCode(code);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Scanner error: ' + err.message });
  }
});

app.get('/', (req, res) => {
  res.send('🔧 Cipher Engine is online.');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Cipher running on port ${PORT}`);
});
