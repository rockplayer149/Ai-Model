const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const { simpleParser } = require('mailparser');
const { convert } = require('html-to-text'); // This line is the fix
const { parse: parseHtml } = require('node-html-parser');
const { parse: parseDomain } = require('tldts');

const { findKeywordForDomain, getDomainsForKeyword, knownDomains } = require('./known_domains.js');

const app = express();
const port = 3001;
const modelApiUrl = 'http://127.0.0.1:5001/predict';

app.use(cors());
const upload = multer({ storage: multer.memoryStorage() });

async function fetchCrtSh(domain) {
    const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
    try {
        const response = await axios.get(url, { timeout: 5000 });
        return response.data || [];
    } catch (error) {
        console.error(`[CRT.SH] Error fetching data for ${domain}:`, error.message);
        return [];
    }
}

async function createForensicReport(mail) {
    const report = {
        senderInfo: {},
        contentAnalysis: {},
        linkAnalysis: { links: [] },
    };

    report.senderInfo = {
        from: mail.from?.text || 'N/A',
        to: mail.to?.text || 'N/A',
        subject: mail.subject || 'No Subject',
        date: mail.date ? mail.date.toISOString() : 'N/A',
    };

    const senderEmail = mail.from?.value[0]?.address || '';
    const senderDomain = senderEmail ? parseDomain(senderEmail).domain : null;

    const html = mail.html || '';
    if (html) {
        const root = parseHtml(html);
        const scriptTags = root.querySelectorAll('script');
        const styleTags = root.querySelectorAll('style');
        const inlineJsCount = root.querySelectorAll('[onclick], [onload], [onmouseover]').length;

        report.contentAnalysis = {
            hasHtml: true,
            scriptTagCount: scriptTags.length,
            styleTagCount: styleTags.length,
            inlineJsCount: inlineJsCount,
            isSuspicious: scriptTags.length > 0 || inlineJsCount > 0,
        };
    } else {
        report.contentAnalysis = { hasHtml: false, isSuspicious: false, scriptTagCount: 0, styleTagCount: 0, inlineJsCount: 0 };
    }

    const anchorTags = html ? parseHtml(html).querySelectorAll('a') : [];
    const httpLinks = anchorTags
        .map(tag => tag.getAttribute('href'))
        .filter(href => href && (href.startsWith('http:') || href.startsWith('https://')));

    if (httpLinks.length === 0) {
        report.linkAnalysis.status = 'No links found in the email body.';
        return report;
    }

    let claimedKeywords = senderDomain ? findKeywordForDomain(senderDomain) : [];
    let verificationStatus = `Sender domain '${senderDomain}' found in local database.`;
    let safeDomainsForCheck = claimedKeywords.length > 0 ? getDomainsForKeyword(claimedKeywords[0]) : [];

    if (senderDomain && claimedKeywords.length === 0) {
        const crtResults = await fetchCrtSh(senderDomain);
        const allKnownKeywords = Object.keys(knownDomains);
        for (const entry of crtResults) {
            const certNames = (entry.name_value || "").toLowerCase().split('\n');
            for (const keyword of allKnownKeywords) {
                if (certNames.some(name => name.includes(keyword)) && !claimedKeywords.includes(keyword)) {
                    claimedKeywords.push(keyword);
                }
            }
        }
        if (claimedKeywords.length > 0) {
            verificationStatus = `Live Check: SUCCESS. Associated '${senderDomain}' with '${claimedKeywords[0]}'.`;
            safeDomainsForCheck = getDomainsForKeyword(claimedKeywords[0]);
            safeDomainsForCheck.push(senderDomain);
        } else {
            verificationStatus = `Live Check: FAILED. Could not verify '${senderDomain}' against any known brand.`;
        }
    }
    
    report.linkAnalysis.verificationStatus = verificationStatus;
    
    for (const linkUrl of httpLinks) {
        const urlDetails = parseDomain(linkUrl);
        const urlDomain = urlDetails.domain;
        let linkStatus = 'Suspicious';

        if (claimedKeywords.length === 0) {
            linkStatus = 'Unverified (Unknown Sender)';
        } else {
            const isSafe = urlDomain && safeDomainsForCheck.some(safeDomain => 
                urlDomain === safeDomain || urlDomain.endsWith('.' + safeDomain)
            );
            if (isSafe) linkStatus = 'Verified Safe';
        }
        report.linkAnalysis.links.push({ url: linkUrl, domain: urlDomain || 'N/A', status: linkStatus });
    }

    return report;
}

app.post('/api/analyze', upload.single('emlfile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }
    try {
        const mail = await simpleParser(req.file.buffer);
        const emailTextForAI = mail.text || convert(mail.html || '');
        
        if (!emailTextForAI.trim()) {
            return res.status(400).json({ error: 'Could not find readable text content.' });
        }

        const modelPromise = axios.post(modelApiUrl, { text: emailTextForAI });
        const forensicPromise = createForensicReport(mail);

        const [modelResponse, forensicReport] = await Promise.all([modelPromise, forensicPromise]);
        
        const finalResult = {
            aiVerdict: modelResponse.data,
            forensicReport: forensicReport
        };

        console.log("✅ Full forensic analysis complete. Sending report.");
        res.json(finalResult);
    } catch (err) {
        console.error("Error during analysis:", err.message);
        res.status(500).json({ error: `Failed to process the email. Details: ${err.message}` });
    }
});

app.listen(port, () => console.log(`Node.js server running on http://localhost:${port}`));