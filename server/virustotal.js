// server/virustotal.js
const axios = require('axios');

// Your VirusTotal API Key is hardcoded here
const VT_API_KEY = "13fb5ffe0f6b4470bcd71e430fd47c4da98986b941fe627f0cee169ea310ff4b";

const cache = new Map();
const CACHE_DURATION_MS = 60 * 60 * 1000; // 1 hour

/**
 * Gets the reputation of a domain from VirusTotal.
 * The API key is sourced from the constant in this file.
 * @param {string} domain - The domain to check.
 * @returns {Promise<object>} The reputation report.
 */
async function getDomainReputation(domain) {
    if (!VT_API_KEY) {
        console.error("[VirusTotal] API Key is not defined in virustotal.js");
        return { status: 'API Key Missing' };
    }
    if (!domain) {
        return { status: 'Invalid Domain' };
    }

    const cached = cache.get(domain);
    if (cached && (Date.now() - cached.timestamp < CACHE_DURATION_MS)) {
        console.log(`[VirusTotal] Returning cached result for ${domain}`);
        return cached.data;
    }

    console.log(`[VirusTotal] Performing live lookup for ${domain}`);
    const options = {
        method: 'GET',
        url: `https://www.virustotal.com/api/v3/domains/${domain}`,
        headers: { 'x-apikey': VT_API_KEY }
    };

    try {
        const response = await axios.request(options);
        const attributes = response.data?.data?.attributes;
        
        if (!attributes) {
            const notFoundResult = { status: 'Not Found in VT', score: 'N/A', isMalicious: false };
            cache.set(domain, { data: notFoundResult, timestamp: Date.now() });
            return notFoundResult;
        }

        const stats = attributes.last_analysis_stats;
        const score = `${stats.malicious + stats.suspicious} / ${stats.harmless + stats.suspicious + stats.malicious}`;
        
        const result = {
            status: 'Found',
            score: score,
            isMalicious: stats.malicious > 0 || stats.suspicious > 0,
        };
        
        cache.set(domain, { data: result, timestamp: Date.now() });
        return result;

    } catch (error) {
        if (error.response && error.response.status === 404) {
             const notFoundResult = { status: 'Not Found in VT', score: 'N/A', isMalicious: false };
             cache.set(domain, { data: notFoundResult, timestamp: Date.now() });
             return notFoundResult;
        }
        console.error(`[VirusTotal] API Error for ${domain}:`, error.message);
        return { status: 'API Error' };
    }
}

module.exports = { getDomainReputation };