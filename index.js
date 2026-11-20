/**
 * TAVARDT Security & Perimeter Audit Action
 * https://tools.tavardt.com/
 */

const https = require('https');
const dns = require('dns').promises;
const fs = require('fs');

async function run() {
  const rawTarget = process.env['INPUT_TARGET-URL'] || process.argv[2];
  const failOnCritical = (process.env['INPUT_FAIL-ON-CRITICAL'] || 'false').toLowerCase() === 'true';

  if (!rawTarget) {
    console.error('Target URL is required.');
    process.exit(1);
  }

  const cleanDomain = rawTarget.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  const targetUrl = `https://${cleanDomain}`;

  console.log(`Starting TAVARDT Security Audit on: ${cleanDomain}`);

  const results = {
    headers: [],
    dmarc: false,
    dmarcRecord: null,
    envExposed: false,
    score: 100,
    criticalCount: 0
  };

  // 1. Check HTTP Security Headers
  try {
    const res = await new Promise((resolve, reject) => {
      const req = https.get(targetUrl, { timeout: 10000 }, resolve);
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Connection timed out')); });
    });

    const headers = res.headers;
    const requiredHeaders = [
      { name: 'Strict-Transport-Security', label: 'HSTS Enforcement', points: 25 },
      { name: 'Content-Security-Policy', label: 'Content Security Policy (CSP)', points: 25 },
      { name: 'X-Frame-Options', label: 'Anti-Clickjacking (X-Frame-Options)', points: 20 },
      { name: 'X-Content-Type-Options', label: 'MIME Sniffing Defense', points: 15 },
      { name: 'Referrer-Policy', label: 'Strict Referrer Policy', points: 15 }
    ];

    requiredHeaders.forEach(h => {
      const present = !!headers[h.name.toLowerCase()];
      results.headers.push({ name: h.label, present });
      if (!present) results.score -= h.points;
    });
  } catch (err) {
    console.warn(`Could not connect to ${targetUrl}: ${err.message}`);
    results.score -= 40;
  }

  // 2. Check DMARC DNS Record
  try {
    const records = await dns.resolveTxt(`_dmarc.${cleanDomain}`);
    const dmarcRecord = records.flat().find(r => r.startsWith('v=DMARC1'));
    if (dmarcRecord) {
      results.dmarc = true;
      results.dmarcRecord = dmarcRecord;
    } else {
      results.criticalCount += 1;
      results.score = Math.max(0, results.score - 30);
    }
  } catch {
    results.criticalCount += 1;
    results.score = Math.max(0, results.score - 30);
  }

  // 3. Check .env Exposure
  try {
    const envRes = await new Promise((resolve, reject) => {
      const req = https.get(`${targetUrl}/.env`, { timeout: 8000 }, resolve);
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    });

    if (envRes.statusCode === 200) {
      results.envExposed = true;
      results.criticalCount += 1;
      results.score = 0;
    }
  } catch {}

  results.score = Math.max(0, Math.min(100, results.score));

  // Console output
  console.log(`\nAudit Complete! Score: ${results.score}/100 | Critical Alerts: ${results.criticalCount}`);

  // Generate GitHub Step Summary
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) {
    let md = `## TAVARDT Security Verification Report for \`${cleanDomain}\`\n\n`;
    md += `**Overall Security Score:** **${results.score}/100** | **Critical Issues:** **${results.criticalCount}**\n\n`;

    md += `### HTTP Security Headers\n\n`;
    md += `| Technical Header | Status |\n|---|---|\n`;
    results.headers.forEach(h => {
      md += `| ${h.name} | ${h.present ? 'PASSED' : 'MISSING (Action Required)'} |\n`;
    });

    md += `\n### Identity & Perimeter Defense\n\n`;
    md += `* **DMARC Record:** ${results.dmarc ? `Configured (\`${results.dmarcRecord}\`)` : 'CRITICAL: Record missing. Domain is vulnerable to email spoofing.'}\n`;
    md += `* **Environment File Protection (.env):** ${results.envExposed ? 'CRITICAL EXPOSURE: Publicly accessible .env file detected!' : 'Protected (HTTP non-200)'}\n\n`;

    md += `\n---\n\n`;
    md += `[Run Full Diagnostic Dossier on TAVARDT Tools](https://tools.tavardt.com/uk/) | [Request Professional Remediation from TAVARDT Engineering](https://ag.tavardt.com/uk/cybersecurity/)\n`;

    fs.appendFileSync(summaryFile, md, 'utf-8');
  }

  if (failOnCritical && results.criticalCount > 0) {
    console.error(`Failing workflow due to ${results.criticalCount} critical vulnerability 발견.`);
    process.exit(1);
  }
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
