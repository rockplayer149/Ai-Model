// server/index.js
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const crypto = require('crypto');
const { simpleParser } = require('mailparser');
const { parse: parseHtml } = require('node-html-parser');
const { parse: parseDomain } = require('tldts');
const { convert } = require('html-to-text');

const { checkAuthenticationHeaders } = require('./rules.js');
const { getDomainReputation } = require('./virustotal.js');

const app = express();
const port = 3001;
const modelApiUrl = 'http://127.0.0.1:5001/predict';

app.use(express.json());
app.use(cors());
const upload = multer({ storage: multer.memoryStorage() });

function analyzeAttachments(mail) {
    const report = { 
        isSuspicious: false, 
        attachments: [], 
        count: mail.attachments?.length || 0 
    };
    
    if (report.count === 0) return report;
    
    const dangerousExtensions = [
        '.exe', '.pif', '.msi', '.com', '.scr', '.hta', '.jar', '.js', 
        '.wsf', '.ps1', '.docm', '.xlsm', '.pptm', '.zip', '.rar', '.7z'
    ];
    
    report.attachments = mail.attachments.map(att => {
        const hash = crypto.createHash('sha256').update(att.content).digest('hex');
        const filename = att.filename || 'unknown';
        const extension = `.${filename.split('.').pop()}`.toLowerCase();
        const isDangerous = dangerousExtensions.includes(extension);
        
        if (isDangerous) report.isSuspicious = true;
        
        return { 
            filename, 
            contentType: att.contentType, 
            size: att.size, 
            sha256: hash, 
            isDangerous, 
            sandboxStatus: 'Not Detonated' 
        };
    });
    
    return report;
}

async function createForensicReport(mail) {
    const senderInfo = { 
        from: mail.from?.text || 'N/A', 
        to: mail.to?.text || 'N/A', 
        subject: mail.subject || 'No Subject', 
        date: mail.date ? mail.date.toISOString() : 'N/A' 
    };
    
    const authResults = checkAuthenticationHeaders(mail);
    const attachmentAnalysis = analyzeAttachments(mail);
    
    const html = mail.html || '';
    const root = html ? parseHtml(html) : null;
    
    const contentAnalysis = { 
        hasHtml: !!html, 
        scriptTagCount: root ? root.querySelectorAll('script').length : 0, 
        inlineJsCount: root ? root.querySelectorAll('[onclick],[onload],[onmouseover]').length : 0 
    };
    
    contentAnalysis.isSuspicious = contentAnalysis.scriptTagCount > 0 || contentAnalysis.inlineJsCount > 0;
    
    const anchorTags = root ? root.querySelectorAll('a') : [];
    const httpLinks = anchorTags
        .map(tag => tag.getAttribute('href'))
        .filter(href => href && (href.startsWith('http:') || href.startsWith('https://')));
    
    const linkAnalysis = { links: [] };
    const uniqueDomains = [...new Set(
        httpLinks.map(link => parseDomain(link).domain).filter(Boolean)
    )];
    
    const reputationPromises = uniqueDomains.map(domain => 
        getDomainReputation(domain).then(reputation => ({ domain, reputation }))
    );
    
    const reputationResults = await Promise.all(reputationPromises);
    const reputationMap = new Map(reputationResults.map(item => [item.domain, item.reputation]));

    linkAnalysis.links = httpLinks.map(linkUrl => {
        const domain = parseDomain(linkUrl).domain;
        return { 
            url: linkUrl, 
            domain: domain || 'N/A', 
            reputation: domain ? reputationMap.get(domain) : { status: 'Invalid Domain' } 
        };
    });
    
    linkAnalysis.isSuspicious = linkAnalysis.links.some(link => link.reputation?.isMalicious);

    return { 
        senderInfo, 
        authResults, 
        attachmentAnalysis, 
        contentAnalysis, 
        linkAnalysis 
    };
}

// Main API endpoint
app.post('/api/analyze', upload.single('emlfile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }
    
    try {
        const mail = await simpleParser(req.file.buffer);
        const emailTextForAI = mail.text || (mail.html ? convert(mail.html, { wordwrap: false }) : '');
        
        if (!emailTextForAI.trim()) {
            return res.status(400).json({ error: 'Could not find readable text content.' });
        }

        console.log("📧 Sending email to AI classifier...");
        const modelPromise = axios.post(modelApiUrl, { text: emailTextForAI });
        const forensicPromise = createForensicReport(mail);

        const [modelResponse, forensicReport] = await Promise.all([modelPromise, forensicPromise]);
        
        // ===== NEW: Enhanced AI verdict processing =====
        const aiData = modelResponse.data;
        
        // Map the new model's verdict to your existing format
        const verdictMap = {
            'ham': 'ham',           // Legitimate
            'spam': 'spam',         // Spam/Marketing
            'phishing': 'phishing'  // Phishing (new!)
        };
        
        const mappedVerdict = verdictMap[aiData.verdict] || 'unknown';
        
        // Enhanced AI verdict with detailed information
        const aiVerdict = {
            verdict: mappedVerdict,
            confidence: aiData.confidence || 0.5,
            classification: aiData.classification || 'Unknown',
            probabilities: aiData.probabilities || {
                legitimate: 0,
                spam: 0,
                phishing: 0
            },
            explanation: aiData.explanation || [],
            // For backwards compatibility
            label: mappedVerdict === 'ham' ? 'Legitimate' : 
                   mappedVerdict === 'spam' ? 'Spam/Marketing' : 
                   mappedVerdict === 'phishing' ? 'Phishing' : 'Unknown'
        };
        
        console.log(`✅ AI Classification: ${aiVerdict.classification} (${(aiVerdict.confidence * 100).toFixed(1)}%)`);
        
        const finalResult = {
            aiVerdict: aiVerdict,
            forensicReport: forensicReport
        };
        
        console.log("✅ Full forensic analysis complete. Sending report.");
        res.json(finalResult);
        
    } catch (err) {
        console.error("❌ Error during analysis:", err.message);
        
        // Check if it's a connection error to the Python API
        if (err.code === 'ECONNREFUSED') {
            return res.status(503).json({ 
                error: 'AI classifier service is not available. Please ensure the Python API is running on port 5001.',
                details: 'Run: python app.py'
            });
        }
        
        res.status(500).json({ 
            error: `Failed to process the email.`, 
            details: err.message 
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        service: 'Email Analysis API',
        port: port 
    });
});

app.listen(port, () => {
    console.log('='.repeat(60));
    console.log('📧 EMAIL ANALYSIS SERVER');
    console.log('='.repeat(60));
    console.log(`✅ Node.js server running on http://localhost:${port}`);
    console.log(`🔗 Connected to AI model at ${modelApiUrl}`);
    console.log('\nEndpoints:');
    console.log('  POST /api/analyze - Analyze email file');
    console.log('  GET  /api/health  - Check server health');
    console.log('='.repeat(60));
});