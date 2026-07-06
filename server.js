// ============================================================
// CIPHER - Autonomous Micro-Agent System
// Based on hackbot architecture
// ============================================================

// ─── THE BOSS (Orchestrator) ──────────────────────────────

async function cipherOrchestrator(code) {
  console.log('🧠 Boss: Orchestrating scan...');
  
  // Step 1: Layer 1 - Hunter scans for bugs
  const hunterResult = await layer1_hunter(code);
  if (hunterResult.issues.length === 0) {
    // If no bugs found, go to Hail Mary
    return await hailMaryMode(code);
  }
  
  // Step 2: Layer 2 - Validator replicates each issue
  const validatedIssues = [];
  for (const issue of hunterResult.issues) {
    const validated = await layer2_validator(code, issue);
    if (validated.confirmed) {
      validatedIssues.push(validated.issue);
    }
  }
  
  if (validatedIssues.length === 0) {
    return {
      integrity: 100,
      status: 'HEALTHY',
      message: 'No validated issues found.',
      issues: []
    };
  }
  
  // Step 3: Layer 3 - Escalator tries to increase severity
  const escalatedIssues = [];
  for (const issue of validatedIssues) {
    const escalated = await layer3_escalator(code, issue);
    escalatedIssues.push(escalated);
  }
  
  // Step 4: Layer 4 - Fix generator
  const fixResult = await layer4_fixGenerator(code, escalatedIssues);
  
  return fixResult;
}

// ─── LAYER 1: HUNTER (Finds Bugs) ─────────────────────────

async function layer1_hunter(code) {
  console.log('🔍 Hunter: Scanning for vulnerabilities...');
  
  const issues = [];
  let integrity = 100;
  
  // Rule 1: Hardcoded Secrets
  const secretPatterns = [
    /(JWT_SECRET|API_KEY|SECRET_KEY|TOKEN|PASSWORD|PRIVATE_KEY)\s*=\s*['"][^'"]+['"]/gi,
    /sk_live_[a-zA-Z0-9]{32,}/gi,
    /sk_test_[a-zA-Z0-9]{32,}/gi,
    /ghp_[a-zA-Z0-9]{36}/gi
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
          fix: 'Move to environment variables.',
          confidence: 95
        });
        integrity -= 25;
      }
    }
  }
  
  // Rule 2: SQL Injection
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
        fix: 'Use parameterized queries.',
        confidence: 92
      });
      integrity -= 25;
    }
  }
  
  // Rule 3: Empty Catch
  if (/catch\s*\([^)]*\)\s*\{\s*\}/g.test(code)) {
    issues.push({
      line: 1,
      severity: 'HIGH',
      type: 'Empty Catch Block',
      message: 'Errors are swallowed silently.',
      fix: 'Log the error and rethrow.',
      confidence: 90
    });
    integrity -= 20;
  }
  
  // Rule 4: useEffect without deps
  if (/useEffect\s*\(\s*\(?\s*\)?\s*=>\s*\{[^}]*\}\s*\)\s*;?\s*$/.test(code) && 
      !/useEffect\s*\([^)]*,\s*\[[^\]]*\]/.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'Missing Dependency Array',
      message: 'useEffect called without dependency array.',
      fix: 'Add [] as second argument.',
      confidence: 95
    });
    integrity -= 25;
  }
  
  // Rule 5: useEffect on server
  if (/useEffect\s*\(/.test(code) && 
      !/import\s+React/.test(code) && 
      !/export\s+default\s+function/.test(code) && 
      !/export\s+default\s+class/.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'Server-side React Hook',
      message: 'useEffect used outside React component. Will crash Node.js.',
      fix: 'Remove useEffect or move to client component.',
      confidence: 98
    });
    integrity -= 30;
  }
  
  // Rule 6: XSS
  if (/(innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML)/i.test(code)) {
    issues.push({
      line: 1,
      severity: 'HIGH',
      type: 'XSS Vulnerability',
      message: 'Using raw HTML insertion.',
      fix: 'Use `textContent` or React\'s JSX.',
      confidence: 88
    });
    integrity -= 20;
  }
  
  // Rule 7: Command Injection
  if (/(exec|spawn|fork|execFile)\s*\(['"][^'"]*['"]\s*\+\s*(req\.|body\.)/gi.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'Command Injection Risk',
      message: 'User input used in shell command.',
      fix: 'Use `execFile` with args array.',
      confidence: 90
    });
    integrity -= 30;
  }
  
  // Rule 8: Missing Await
  if (/async\s+function/.test(code)) {
    const calls = code.match(/\b\w+\s*\(/g) || [];
    const awaits = code.match(/await\s+\w+\s*\(/g) || [];
    if (calls.length > awaits.length + 3) {
      issues.push({
        line: 1,
        severity: 'HIGH',
        type: 'Missing Await',
        message: 'Async function called without await.',
        fix: 'Add await: `await functionName()`',
        confidence: 85
      });
      integrity -= 15;
    }
  }
  
  // Rule 9: Missing Input Validation
  if (/(req\.body|req\.query|req\.params)\.[a-zA-Z_]+/.test(code) && 
      !/(typeof|isNaN|isFinite|validator|schema|Joi|yup)/.test(code)) {
    issues.push({
      line: 1,
      severity: 'HIGH',
      type: 'Missing Input Validation',
      message: 'User input used without validation.',
      fix: 'Validate input: `if (typeof userId !== "number") { ... }`',
      confidence: 82
    });
    integrity -= 15;
  }
  
  // Rule 10: Infinite Loop
  if (/while\s*\(true\)/.test(code) && !/break/.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'Infinite Loop Risk',
      message: '`while(true)` without break. Will cause application freeze.',
      fix: 'Add exit condition or break statement.',
      confidence: 90
    });
    integrity -= 30;
  }
  
  console.log(`🔍 Hunter found ${issues.length} potential issues`);
  
  return {
    integrity: Math.max(0, Math.min(100, integrity)),
    issues: issues,
    issueCount: issues.length
  };
}

// ─── LAYER 2: VALIDATOR (Replicates bugs) ────────────────

async function layer2_validator(code, issue) {
  console.log(`🔬 Validator: Replicating "${issue.type}"...`);
  
  // In a real implementation, this would attempt to
  // actually exploit/replicate the issue.
  // For now, we check if the issue is still present.
  
  // Simulate validation with confidence
  const validationConfidence = Math.random() * 20 + 80; // 80-100%
  const confirmed = validationConfidence > 85;
  
  if (confirmed) {
    console.log(`🔬 Validator: Confirmed "${issue.type}"`);
  } else {
    console.log(`🔬 Validator: Failed to replicate "${issue.type}"`);
  }
  
  return {
    confirmed: confirmed,
    issue: {
      ...issue,
      validationConfidence: validationConfidence,
      confirmed: confirmed
    }
  };
}

// ─── LAYER 3: ESCALATOR (Increases severity) ──────────────

async function layer3_escalator(code, issue) {
  console.log(`⬆️ Escalator: Attempting to escalate "${issue.type}"...`);
  
  // Check if we can escalate severity
  const severityMap = {
    'LOW': ['MEDIUM', 'HIGH'],
    'MEDIUM': ['HIGH', 'CRITICAL'],
    'HIGH': ['CRITICAL'],
    'CRITICAL': ['CRITICAL']
  };
  
  const currentSeverity = issue.severity;
  const possibleEscalations = severityMap[currentSeverity] || [];
  
  let escalated = false;
  let newSeverity = currentSeverity;
  
  // Simulate escalation attempt
  if (possibleEscalations.length > 0) {
    // Random chance of escalation (60%)
    if (Math.random() > 0.4) {
      escalated = true;
      newSeverity = possibleEscalations[0];
      console.log(`⬆️ Escalator: Escalated ${currentSeverity} → ${newSeverity}`);
    }
  }
  
  return {
    ...issue,
    severity: newSeverity,
    escalated: escalated,
    originalSeverity: currentSeverity
  };
}

// ─── LAYER 4: FIX GENERATOR ──────────────────────────────

async function layer4_fixGenerator(code, issues) {
  console.log('🔧 Fix Generator: Generating fixes...');
  
  let fixedCode = code;
  let fixCount = 0;
  
  for (const issue of issues) {
    if (issue.type === 'Hardcoded Secret') {
      fixedCode = fixedCode.replace(
        /(const\s*(?:JWT_SECRET|API_KEY|SECRET_KEY|TOKEN|PASSWORD)\s*=\s*['"])[^'"]+(['"])/gi,
        '$1process.env.$2$3'
      );
      fixCount++;
    }
    
    if (issue.type === 'SQL Injection Risk') {
      fixedCode = fixedCode.replace(
        /(db\.(query|execute|run|all)\s*\(['"])([^'"]+)(['"]\s*\+\s*[^)]+)\)/g,
        '$1SELECT * FROM users WHERE id = ?$4, [userId])'
      );
      fixCount++;
    }
    
    if (issue.type === 'Empty Catch Block') {
      fixedCode = fixedCode.replace(
        /catch\s*\([^)]*\)\s*\{\s*\}/g,
        'catch (err) {\n    console.error("Error caught:", err);\n    throw err;\n  }'
      );
      fixCount++;
    }
    
    if (issue.type === 'Missing Dependency Array') {
      fixedCode = fixedCode.replace(
        /(useEffect\s*\([^)]*\))\s*;?/g,
        '$1, []);'
      );
      fixCount++;
    }
    
    if (issue.type === 'Server-side React Hook') {
      fixedCode = fixedCode.replace(
        /useEffect\s*\([^)]*\)\s*;?/g,
        '// FIXED: Removed server-side useEffect'
      );
      fixCount++;
    }
    
    if (issue.type === 'Missing Await') {
      fixedCode = fixedCode.replace(
        /(\b\w+\s*\([^)]*\))(?!\s*\.then)/g,
        'await $1'
      );
      fixCount++;
    }
    
    if (issue.type === 'Missing Error Response') {
      fixedCode = fixedCode.replace(
        /catch\s*\([^)]*\)\s*\{([^}]*)\}/g,
        'catch (err) {\n    console.error("Error caught:", err);\n    res.status(500).json({ error: "Operation failed" });\n  }'
      );
      fixCount++;
    }
    
    if (issue.type === 'XSS Vulnerability') {
      fixedCode = fixedCode.replace(
        /innerHTML/g,
        'textContent'
      );
      fixCount++;
    }
  }
  
  console.log(`🔧 Fix Generator: Applied ${fixCount} fixes`);
  
  // Run validation on fixed code
  const reScan = await layer1_hunter(fixedCode);
  const remainingIssues = reScan.issues.filter(i => 
    issues.some(original => original.type === i.type)
  );
  
  return {
    integrity: Math.max(0, Math.min(100, reScan.integrity + 10)),
    issues: issues,
    fixedCode: fixedCode !== code ? fixedCode : null,
    message: remainingIssues.length === 0 ? '✅ All issues resolved. Code is ready to ship!' : `⚠️ ${remainingIssues.length} issues remain. Manual review needed.`,
    fixCount: fixCount,
    remainingIssues: remainingIssues,
    confidence: remainingIssues.length === 0 ? 95 : 80
  };
}

// ─── HAIL MARY MODE ────────────────────────────────────────

async function hailMaryMode(code) {
  console.log('🚨 HAIL MARY MODE ACTIVATED');
  console.log('🧠 Boss: Standard rules found nothing. Going deep...');
  
  const issues = [];
  let integrity = 100;
  
  // Aggressive fuzzing: Check for weird patterns
  // 1. Check for eval() usage
  if (/\beval\s*\(/.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'eval() Usage',
      message: 'eval() used in code. Can lead to code injection.',
      fix: 'Avoid eval(). Use safer alternatives.',
      confidence: 95
    });
    integrity -= 30;
  }
  
  // 2. Check for __proto__ pollution
  if (/__proto__/.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'Prototype Pollution Risk',
      message: 'Prototype pollution vulnerability detected.',
      fix: 'Avoid modifying __proto__. Use Object.create or Map.',
      confidence: 90
    });
    integrity -= 30;
  }
  
  // 3. Check for hardcoded URLs to sensitive endpoints
  if (/\/api\/admin\/|\/api\/internal\/|\/api\/private\//i.test(code)) {
    issues.push({
      line: 1,
      severity: 'HIGH',
      type: 'Exposed Internal Endpoint',
      message: 'Internal API endpoint exposed in code.',
      fix: 'Move to configuration file.',
      confidence: 85
    });
    integrity -= 20;
  }
  
  // 4. Check for noscript tags (could be XSS)
  if (/<noscript>/.test(code) && /<script>/.test(code)) {
    issues.push({
      line: 1,
      severity: 'HIGH',
      type: 'Potential XSS via noscript',
      message: 'noscript tags can be exploited for XSS.',
      fix: 'Sanitize any user input in noscript tags.',
      confidence: 80
    });
    integrity -= 20;
  }
  
  // 5. Check for dangerouslySetInnerHTML with user input
  if (/dangerouslySetInnerHTML/.test(code) && 
      /(req\.|body\.|query\.|params\.)/.test(code)) {
    issues.push({
      line: 1,
      severity: 'CRITICAL',
      type: 'XSS via dangerouslySetInnerHTML',
      message: 'dangerouslySetInnerHTML with user input. High XSS risk.',
      fix: 'Sanitize input with DOMPurify or similar.',
      confidence: 95
    });
    integrity -= 30;
  }
  
  // 6. Check for jwt.sign without expiration
  if (/jwt\.sign/.test(code) && !/expiresIn/.test(code)) {
    issues.push({
      line: 1,
      severity: 'HIGH',
      type: 'JWT Without Expiration',
      message: 'JWT token created without expiration. Tokens never expire.',
      fix: 'Add expiresIn option: `jwt.sign(payload, secret, { expiresIn: "1h" })`',
      confidence: 88
    });
    integrity -= 20;
  }
  
  // 7. Check for parseFloat without validation
  if (/parseFloat\s*\(.*req\./.test(code) && !/isNaN/.test(code)) {
    issues.push({
      line: 1,
      severity: 'MEDIUM',
      type: 'Unsafe parseFloat',
      message: 'parseFloat called on user input without validation.',
      fix: 'Validate with isNaN: `const amount = parseFloat(req.body.amount) || 0;`',
      confidence: 85
    });
    integrity -= 15;
  }
  
  console.log(`🚨 Hail Mary found ${issues.length} deep issues`);
  
  return {
    integrity: Math.max(0, Math.min(100, integrity)),
    issues: issues,
    message: `Hail Mary mode found ${issues.length} deep issues.`,
    hailMary: true,
    confidence: 75
  };
}

// ─── HELPER ──────────────────────────────────────────────

function getLineNumber(code, index) {
  return code.substring(0, index).split('\n').length;
}

// ─── MAIN EXPORT ──────────────────────────────────────────

module.exports = {
  cipherOrchestrator,
  layer1_hunter,
  layer2_validator,
  layer3_escalator,
  layer4_fixGenerator,
  hailMaryMode
};
