const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const { simpleParser } = require('mailparser');
const { convert } = require('html-to-text');
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

async function analyzeUrls(html, fromHeader = '') {
    if (!html) return { containsUrls: false };

    const root = parseHtml(html);
    const anchorTags = root.querySelectorAll('a');
    const httpLinks = anchorTags
        .map(tag => tag.getAttribute('href'))
        .filter(href => href && (href.startsWith('http:') || href.startsWith('https://')));

    if (httpLinks.length === 0) {
        return { containsUrls: true, isSuspicious: false, reason: "No web links found." };
    }

    const senderEmail = fromHeader;
    const senderDomain = senderEmail ? parseDomain(senderEmail).domain : null;
    if (!senderDomain) {
        return { containsUrls: true, isSuspicious: false, reason: "Could not identify a sender domain." };
    }

    let claimedKeywords = findKeywordForDomain(senderDomain);
    let verificationStatus = `Sender domain '${senderDomain}' was found in the local database.`;
    let safeDomainsForCheck = claimedKeywords.length > 0 ? getDomainsForKeyword(claimedKeywords[0]) : [];

    if (claimedKeywords.length === 0) {
        console.log(`[Live Check] Sender '${senderDomain}' not in local DB. Querying crt.sh...`);
        const crtResults = await fetchCrtSh(senderDomain);
        const allKnownKeywords = Object.keys(knownDomains);

        for (const entry of crtResults) {
            const certNames = (entry.name_value || "").toLowerCase().split('\n');
            for (const keyword of allKnownKeywords) {
                if (certNames.some(name => name.includes(keyword))) {
                    if (!claimedKeywords.includes(keyword)) claimedKeywords.push(keyword);
                }
            }
        }
        
        if (claimedKeywords.length > 0) {
            const primaryKeyword = claimedKeywords[0];
            verificationStatus = `Live Check: SUCCESS. Sender domain '${senderDomain}' has a certificate associated with '${primaryKeyword}'.`;
            safeDomainsForCheck = getDomainsForKeyword(primaryKeyword);
            // --- THIS IS THE FIX ---
            // After verifying the sender, add its own domain to the list of safe domains for this check.
            safeDomainsForCheck.push(senderDomain);
            // --------------------
        } else {
            verificationStatus = `Live Check: FAILED. Could not associate sender domain '${senderDomain}' with any known brand.`;
        }
    }

    const report = {
        containsUrls: true,
        isSuspicious: false,
        claimedSender: claimedKeywords.length > 0 ? claimedKeywords[0] : senderDomain,
        safeDomains: safeDomainsForCheck,
        suspiciousLinks: [],
        safeLinks: [],
        verificationStatus: verificationStatus,
        reason: ""
    };

    if (claimedKeywords.length === 0) {
        report.isSuspicious = true;
        report.suspiciousLinks = httpLinks.map(link => ({
            url: link,
            domain: parseDomain(link).domain || 'N/A',
            verification: "Cannot verify link because sender is unknown."
        }));
        report.reason = "Sender is from an unknown domain and could not be verified. All links should be treated with caution.";
        return report;
    }

    for (const linkUrl of httpLinks) {
        const urlDetails = parseDomain(linkUrl);
        const urlDomain = urlDetails.domain;

        const isSafe = urlDomain && report.safeDomains.some(safeDomain => 
            urlDomain === safeDomain || urlDomain.endsWith('.' + safeDomain)
        );

        if (isSafe) {
            report.safeLinks.push({ url: linkUrl, domain: urlDomain });
        } else {
            report.isSuspicious = true;
            report.suspiciousLinks.push({ 
                url: linkUrl, 
                domain: urlDomain || 'N/A',
                verification: `This domain is not a known safe domain for '${report.claimedSender}'.`
            });
        }
    }

    if (report.isSuspicious) {
        report.reason = `The sender was verified as '${report.claimedSender}', but some links go to untrusted domains.`;
    } else {
        report.reason = `The sender was verified as '${report.claimedSender}', and all links match their known domains.`;
    }

    return report;
}

// Main app.post route (remains unchanged)
app.post('/api/analyze', upload.single('emlfile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }
    try {
        const mail = await simpleParser(req.file.buffer);
        const emailHtmlForUrls = mail.html || '';
        let emailTextForAI = '';
        if (emailHtmlForUrls) {
            emailTextForAI = convert(emailHtmlForUrls, { wordwrap: false, selectors: [{ selector: 'img', format: 'skip' }]});
        } else if (mail.text) {
            emailTextForAI = mail.text;
        }
        const fromHeader = mail.from?.value[0]?.address || '';
        if (!emailTextForAI.trim()) {
            return res.status(400).json({ error: 'Could not find readable text content in the email.' });
        }
        const modelPromise = axios.post(modelApiUrl, { text: emailTextForAI });
        const urlAnalysisPromise = analyzeUrls(emailHtmlForUrls, fromHeader);
        const [modelResponse, urlAnalysis] = await Promise.all([modelPromise, urlAnalysisPromise]);
        const finalResult = { ...modelResponse.data, urlAnalysis };
        console.log("✅ Analysis complete. Sending combined report.");
        res.json(finalResult);
    } catch (err) {
        console.error("Error during analysis:", err.message);
        res.status(500).json({ error: `Failed to process the email. Details: ${err.message}` });
    }
});

app.listen(port, () => console.log(`Node.js server running on http://localhost:${port}`));

