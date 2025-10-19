// server/rules.js

/**
 * Checks for SPF, DKIM, and DMARC pass/fail results in the headers.
 * This is a basic check; real-world parsers are more complex.
 * @param {object} mail - The parsed email object from mailparser.
 * @returns {object} An object with the status of each authentication method.
 */
function checkAuthenticationHeaders(mail) {
    const results = {
        spf: { pass: false, text: "SPF record not found or failed." },
        dkim: { pass: false, text: "DKIM signature not found or invalid." },
        dmarc: { pass: false, text: "DMARC policy not found or failed." },
    };

    const authResultsHeader = mail.headers?.get('authentication-results') || '';
    const authResultsString = Array.isArray(authResultsHeader) ? authResultsHeader.join(' ') : String(authResultsHeader);

    if (authResultsString.includes('spf=pass')) {
        results.spf = { pass: true, text: "SPF alignment passed." };
    }
    if (authResultsString.includes('dkim=pass')) {
        results.dkim = { pass: true, text: "DKIM signature verified." };
    }
    if (authResultsString.includes('dmarc=pass')) {
        results.dmarc = { pass: true, text: "DMARC alignment passed." };
    }

    return results;
}

/**
 * Checks for potentially dangerous attachment file types.
 * @param {object} mail - The parsed email object from mailparser.
 * @returns {object} An object containing a list of attachments and a suspicion flag.
 */
function checkForBadAttachments(mail) {
    const report = {
        isSuspicious: false,
        attachments: [],
    };

    if (!mail.attachments || mail.attachments.length === 0) {
        return report;
    }

    // A list of common high-risk file extensions
    const dangerousExtensions = [
        '.exe', '.pif', '.application', '.gadget', '.msi', '.msp', '.com', '.scr',
        '.hta', '.cpl', '.msc', '.jar', '.js', '.jse', '.ws', '.wsf', '.wsc',
        '.wsh', '.ps1', '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2', '.msh',
        '.msh1', '.msh2', '.mshxml', '.msh1xml', '.msh2xml', '.scf', '.lnk',
        '.inf', '.reg', '.docm', '.dotm', '.xlsm', '.xltm', '.xlam', '.pptm',
        '.potm', '.ppam', '.ppsm', '.sldm', '.zip', '.rar', '.7z'
    ];

    report.attachments = mail.attachments.map(att => {
        const filename = att.filename || 'unknown';
        const extension = `.${filename.split('.').pop()}`.toLowerCase();
        const isDangerous = dangerousExtensions.includes(extension);
        
        if (isDangerous) {
            report.isSuspicious = true;
        }

        return {
            filename,
            contentType: att.contentType,
            size: att.size,
            isDangerous,
        };
    });

    return report;
}

module.exports = {
    checkAuthenticationHeaders,
    checkForBadAttachments,
};