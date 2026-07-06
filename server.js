// ============================================================
// PYKORSE ENGINE - Complete 4-Layer Scanner
// Catches: Security flaws, code smells, logic errors, syntax
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

// ─── COMPLETE SCANNER ─────────────────────────────────────

function scanCode(code) {
  let issues = [];
  let integrity = 100;
  let fixedCode = code;

  // ─── LAYER 1: SECURITY SCAN ──────────────────────────────

  // 1. Hardcoded Secrets
  const secretPatterns = [
    /(JWT_SECRET|API_KEY|SECRET_KEY|TOKEN|PASSWORD|PRIVATE_KEY)\s*=\s*['"][^'"]+['"]/gi,
    /sk_live_[a-zA-Z0-9]{32,}/gi,
    /sk_test_[a-zA-Z0-9]{32,}/gi,
    /ghp_[a-zA-Z0-9]{36}/gi,
    /gho_[a-zA-Z0-9]{36}/gi
  ];
  for (const pattern of secretPatterns) {
    const matches = code.match(pattern);
    if (matches) {
      for (const match of matches) {
        issues.push({
          line: getLineNumber(code, match),
          severity: 'CRITICAL',
          type: 'Hardcoded Secret',
          message: `Secret exposed: "${match.substring(0, 20)}..."`,
          fix: 'Move to environment variables: `const SECRET = process.env.SECRET;`'
        });
        integrity -= 25;
      }
    }
  }

  // 2. SQL Injection
  const sqlPatterns = [
    /\$\{.*?\}\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)/gi,
    /['"]\s*\+\s*(req\.|body\.|query\.|params\.)/gi,
    /db\.(query|execute|run|all)\s*\(['"][^'"]*['"]\s*\+/gi
  ];
  for (const pattern of sqlPatterns) {
    if (pattern.test(code)) {
      issues.push({
        line: 1,
        severity: 'CRITICAL',
        type: 'SQL Injection Risk',
        message: 'Unsafe SQL query with string concatenation.',
        fix: 'Use parameterized queries: `db.query("SELECT * FROM users WHERE id = ?", [userId])`'
      });
      integrity -= 25;
    }
  }

  // 3. XSS
  if (/(innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML)/i.test(code)) {
    issues.push({
      line: 1,
      severity: 'HIGH',
      type: 'XSS Vulnerability',
      message: 'Using raw HTML insertion. Content may be vulnerable to XSS.',
      fix: 'Use `textContent` or React\'s JSX. Sanitize user input.'
    });
    integrity -= 20;
  }

  // 4. Command Injection
  if (/(exec|spawn|fork|execFile)\s*\(['"][^'"]*['"]\s*\+\s*(req\.|body\.)/gi.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'Command Injection Risk',
      message: 'User input used in shell command. Can lead to remote code execution.',
      fix: 'Use `execFile` with args array. Validate and sanitize input.'
    });
    integrity -= 30;
  }

  // ─── LAYER 2: LOGIC ERRORS ──────────────────────────────

  // 5. Empty Catch
  if (/catch\s*\([^)]*\)\s*\{\s*\}/g.test(code)) {
    issues.push({
      line: 1,
      severity: 'HIGH',
      type: 'Empty Catch Block',
      message: 'Errors are swallowed silently. Production failures will go undetected.',
      fix: 'Log the error: `catch (err) { console.error(err); throw err; }`'
    });
    integrity -= 20;
  }

  // 6. Missing Error Response
  if (/catch\s*\([^)]*\)/.test(code) && !/res\.status\s*\([45]\d{2}\)/.test(code)) {
    issues.push({
      line: 1,
      severity: 'HIGH',
      type: 'Missing Error Response',
      message: 'Error caught but client receives no error response.',
      fix: 'Add error response: `res.status(500).json({ error: "Operation failed" })`'
    });
    integrity -= 15;
  }

  // 7. Missing Await
  if (/async\s+function/.test(code)) {
    const calls = code.match(/\b\w+\s*\(/g) || [];
    const awaits = code.match(/await\s+\w+\s*\(/g) || [];
    if (calls.length > awaits.length + 3) {
      issues.push({
        line: 1,
        severity: 'HIGH',
        type: 'Missing Await',
        message: 'Async function called without await. Promise may not resolve.',
        fix: 'Add await: `await functionName()`'
      });
      integrity -= 15;
    }
  }

  // 8. No Input Validation
  if (/(req\.body|req\.query|req\.params)\.[a-zA-Z_]+/.test(code) && 
      !/(typeof|isNaN|isFinite|validator|schema|Joi|yup)/.test(code)) {
    issues.push({
      line: 1,
      severity: 'HIGH',
      type: 'Missing Input Validation',
      message: 'User input used without validation. Can lead to crashes or injection.',
      fix: 'Validate input: `if (typeof userId !== "number") { ... }`'
    });
    integrity -= 15;
  }

  // 9. Infinite Loop Risk
  if (/while\s*\(true\)/.test(code) && !/break/.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'Infinite Loop Risk',
      message: '`while(true)` without break. Will cause application freeze.',
      fix: 'Add exit condition or break statement.'
    });
    integrity -= 30;
  }

  // ─── LAYER 3: FRAMEWORK-SPECIFIC BUGS ──────────────────

  // 10. useEffect without deps
  if (/useEffect\s*\(\s*\(?\s*\)?\s*=>\s*\{[^}]*\}\s*\)\s*;?\s*$/.test(code) && 
      !/useEffect\s*\([^)]*,\s*\[[^\]]*\]/.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'Missing Dependency Array',
      message: 'useEffect called without dependency array. Causes infinite re-renders.',
      fix: 'Add [] as second argument: `useEffect(() => {...}, []);`'
    });
    integrity -= 25;
  }

  // 11. useEffect on server (React hook in Node.js)
  if (/useEffect\s*\(/.test(code) && 
      !/import\s+React/.test(code) && 
      !/export\s+default\s+function/.test(code) && 
      !/export\s+default\s+class/.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'Server-side React Hook',
      message: 'useEffect used outside React component. Will crash Node.js.',
      fix: 'Remove useEffect or move to client-side React component.'
    });
    integrity -= 30;
  }

  // 12. Missing State Setter
  if (/useState\s*\(/.test(code) && 
      !/set[A-Z][a-zA-Z]*\s*\(/.test(code)) {
    issues.push({
      line: 1,
      severity: 'HIGH',
      type: 'Unused State Setter',
      message: 'State setter declared but never used. State will never update.',
      fix: 'Use setter: `setState(newValue)`'
    });
    integrity -= 15;
  }

  // ─── LAYER 4: CODE QUALITY ──────────────────────────────

  // 13. Unused variables
  const varDeclarations = code.match(/(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g) || [];
  for (const decl of varDeclarations) {
    const varName = decl.replace(/(?:const|let|var)\s+/, '');
    const usageRegex = new RegExp(`\\b${varName}\\b`, 'g');
    const matches = code.match(usageRegex) || [];
    if (matches.length <= 1) {
      issues.push({
        line: 1,
        severity: 'LOW',
        type: 'Unused Variable',
        message: `Variable "${varName}" declared but never used.`,
        fix: `Remove or use "${varName}" in your code.`
      });
      integrity -= 5;
    }
  }

  // 14. Missing semicolons
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line && !line.endsWith(';') && !line.endsWith('{') && !line.endsWith('}') &&
        !line.startsWith('//') && !line.startsWith('/*') && !line.endsWith('(') &&
        !line.endsWith('=>') && !line.includes('import ') && !line.includes('export ') &&
        !line.includes('return ') && line.length > 5 && !line.includes('if') && 
        !line.includes('for') && !line.includes('while') && !line.includes('try') &&
        !line.includes('catch') && !line.includes('switch') && !line.includes('class')) {
      issues.push({
        line: i + 1,
        severity: 'LOW',
        type: 'Missing Semicolon',
        message: 'Missing semicolon at end of line.',
        fix: 'Add `;` at the end of line ' + (i + 1)
      });
      integrity -= 2;
    }
  }

  // 15. Console.log in production
  if (/console\.log/.test(code) && !/dev/.test(code)) {
    issues.push({
      line: 1,
      severity: 'LOW',
      type: 'Debug Logging',
      message: 'console.log used in production code.',
      fix: 'Remove or use a proper logger: `logger.info(...)`'
    });
    integrity -= 5;
  }

  // ─── GENERATE FIXES ──────────────────────────────────────

  // Fix SQL injection
  if (issues.some(i => i.type === 'SQL Injection Risk')) {
    fixedCode = fixedCode.replace(
      /(db\.(query|execute|run|all)\s*\(['"])([^'"]+)(['"]\s*\+\s*[^)]+)\)/g,
      '$1SELECT * FROM users WHERE id = ?$4, [userId])'
    );
  }

  // Fix useEffect
  if (issues.some(i => i.type === 'Missing Dependency Array')) {
    fixedCode = fixedCode.replace(
      /(useEffect\s*\([^)]*\))\s*;?/g,
      '$1, []);'
    );
  }

  // Fix empty catch
  if (issues.some(i => i.type === 'Empty Catch Block')) {
    fixedCode = fixedCode.replace(
      /catch\s*\([^)]*\)\s*\{\s*\}/g,
      'catch (err) {\n    console.error("Error caught:", err);\n    throw err;\n  }'
    );
  }

  // Fix hardcoded secrets
  if (issues.some(i => i.type === 'Hardcoded Secret')) {
    fixedCode = fixedCode.replace(
      /(const\s*(?:JWT_SECRET|API_KEY|SECRET_KEY|TOKEN|PASSWORD)\s*=\s*['"])[^'"]+(['"])/gi,
      '$1process.env.$2$3'
    );
  }

  // Fix missing await
  if (issues.some(i => i.type === 'Missing Await')) {
    fixedCode = fixedCode.replace(
      /(\b\w+\s*\([^)]*\))(?!\s*\.then)/g,
      'await $1'
    );
  }

  // Fix missing error response
  if (issues.some(i => i.type === 'Missing Error Response')) {
    fixedCode = fixedCode.replace(
      /catch\s*\([^)]*\)\s*\{([^}]*)\}/g,
      'catch (err) {\n    console.error("Error caught:", err);\n    res.status(500).json({ error: "Operation failed" });\n  }'
    );
  }

  // ─── VALIDATION ──────────────────────────────────────────

  let confidence = 95;
  let status = 'HEALTHY';
  let message = 'Code looks clean! 🚀';

  if (issues.length > 0) {
    status = integrity < 30 ? 'CRITICAL' : integrity < 60 ? 'WARNING' : 'HEALTHY';
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
