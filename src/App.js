import React, { useState, useEffect } from 'react';

// --- UI SUB-COMPONENTS FOR THE FORENSIC REPORT ---
// (These components are unchanged from the previous version)

const StatusPill = ({ pass, text }) => (
    <span className={`px-2 py-1 text-xs font-bold rounded-full ${pass ? 'bg-green-900/75 text-green-300' : 'bg-red-900/75 text-red-400'}`}>
        {text}
    </span>
);

const Section = ({ title, children }) => (
    <div className="mt-4">
        <h4 className="font-bold text-green-300">[ {title} ]</h4>
        <div className="mt-2 text-sm space-y-1 pl-4 border-l-2 border-green-900/50">{children}</div>
    </div>
);

const InfoRow = ({ label, value }) => (
    <div className="grid grid-cols-3 gap-2 py-1">
        <span className="col-span-1 font-semibold text-green-300">{label}:</span>
        <span className="col-span-2 text-green-400 break-words">{value}</span>
    </div>
);

const LinkRow = ({ link }) => {
    let reputationText = 'N/A';
    let reputationColor = 'text-gray-500';
    if (link.reputation) {
        if (link.reputation.status === 'Found') {
            reputationText = `VT Score: ${link.reputation.score}`;
            if (link.reputation.isMalicious) {
                reputationColor = 'text-red-500 font-bold animate-pulse';
            } else {
                reputationColor = 'text-green-400';
            }
        } else {
            reputationText = link.reputation.status;
            reputationColor = 'text-yellow-400';
        }
    }
    return (
        <div className="border-t border-green-900/50 py-2">
            <div className="flex items-center justify-between">
                <span className="text-sm font-semibold text-cyan-400">{link.domain}</span>
                <span className={`text-xs font-mono ${reputationColor}`}>{reputationText}</span>
            </div>
            <p className="text-xs text-green-600 break-all mt-1" title={link.url}>{link.url}</p>
        </div>
    );
};

const AttachmentRow = ({ att }) => (
     <div className="border-t border-green-900/50 py-2">
        <div className="flex justify-between items-center">
            <p className="font-semibold text-cyan-400">{att.filename}</p>
            <StatusPill pass={!att.isDangerous} text={att.isDangerous ? 'DANGEROUS TYPE' : 'SAFE TYPE'}/>
        </div>
        <div className="text-xs text-green-600 mt-1 space-y-1">
            <p>SHA256: <span className="text-gray-400 break-all">{att.sha256}</span></p>
            <p>Sandbox: <span className="text-yellow-400">{att.sandboxStatus}</span></p>
        </div>
    </div>
);


// Main App component with simplified UI
function App() {
    const [selectedFile, setSelectedFile] = useState(null);
    const [analysisResult, setAnalysisResult] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    
    const [loadingText, setLoadingText] = useState('Initiating scan...');
    const loadingMessages = [ 'Parsing MIME structure...', 'Analyzing headers...', 'Hashing attachments...', 'Querying VirusTotal API...', 'Awaiting AI verdict...', 'Compiling forensic report...'];
    useEffect(() => {
        let interval;
        if (isLoading) {
            let i = 0;
            interval = setInterval(() => {
                i = (i + 1) % loadingMessages.length;
                setLoadingText(loadingMessages[i]);
            }, 750);
        }
        return () => clearInterval(interval);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [isLoading]);

    const handleFileChange = (e) => {
        const file = e.target.files[0];
        if (file && file.name.toLowerCase().endsWith('.eml')) {
            setSelectedFile(file);
            setAnalysisResult(null);
            setError('');
        } else {
            setSelectedFile(null);
            setError('ERROR: Invalid file type. Please upload a .eml file.');
        }
    };

    const handleSubmit = async () => {
        if (!selectedFile) return;

        setIsLoading(true);
        setAnalysisResult(null);
        setError('');

        const formData = new FormData();
        formData.append('emlfile', selectedFile);
        // No longer sending the API key from the frontend

        try {
            const response = await fetch('http://localhost:3001/api/analyze', {
                method: 'POST',
                body: formData,
            });
            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Server returned an error.');
            }
            const result = await response.json();
            
            const verdict = result.aiVerdict.verdict?.toLowerCase();
            result.displayVerdict = verdict === 'ham' 
                ? 'SAFE' 
                : (verdict === 'phishing' || verdict === 'spam' 
                    ? 'POTENTIALLY MALICIOUS' 
                    : 'UNKNOWN');
            
            setAnalysisResult(result);
        } catch (err) {
            setError(`ANALYSIS FAILED: ${err.message}`);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="bg-black text-green-400 font-mono min-h-screen p-4 sm:p-8">
            <div className="max-w-4xl mx-auto border-2 border-green-900/50 shadow-[0_0_20px_rgba(52,211,153,0.3)] p-4 sm:p-6">
                <header className="text-center border-b-2 border-green-900/50 pb-4">
                    <h1 className="text-2xl sm:text-4xl font-bold animate-glow">[ EML THREAT ANALYZER ]</h1>
                    <p className="text-xs text-green-600 mt-2">v4.0 - Attachment Hashing & Reputation Modules Active</p>
                </header>

                <main className="mt-6">
                     <div className="border border-green-900/50 p-4">
                        <label htmlFor="file-input" className="cursor-pointer block text-center font-medium text-cyan-400 hover:text-cyan-300 border-2 border-dashed border-green-700/50 p-8 h-full flex flex-col justify-center items-center hover:border-cyan-400">
                            {selectedFile ? <span>TARGET ACQUIRED:<br/>{selectedFile.name}</span> : 'SELECT .EML FILE'}
                        </label>
                        <input type="file" id="file-input" className="hidden" accept=".eml" onChange={handleFileChange} />
                    </div>
                    {error && <p className="text-red-500 text-sm mt-4 text-center">{error}</p>}
                    <div className="mt-4">
                        <button 
                            onClick={handleSubmit} 
                            disabled={!selectedFile || isLoading} 
                            className="w-full bg-green-900/50 text-green-300 font-bold py-3 px-8 border-2 border-green-700/50 hover:bg-green-800/50 hover:text-white transition-all duration-300"
                        >
                           {isLoading ? '...ANALYZING...' : 'EXECUTE ANALYSIS'}
                        </button>
                    </div>
                </main>

                {isLoading && (
                     <Section title="ANALYSIS IN PROGRESS">
                        <p className="text-cyan-400">{loadingText}<span className="animate-blink">|</span></p>
                     </Section>
                )}

                {analysisResult && (
                    <section className="mt-6 border-2 border-green-900/50 p-4 animate-fade-in">
                        <h3 className="font-bold text-lg">[ FORENSIC REPORT ]</h3>
                        
                        <div className={`mt-4 text-center p-2 border-2 ${analysisResult.displayVerdict === 'SAFE' ? 'border-green-400 bg-green-900/50' : 'border-red-500 bg-red-900/50'}`}>
                            <h4 className="text-xl font-bold">AI VERDICT: {analysisResult.displayVerdict}</h4>
                        </div>
                        
                        <div className="mt-4 border border-green-900/50 p-4 text-sm">
                            <Section title="Header Analysis">
                                <InfoRow label="From" value={analysisResult.forensicReport.senderInfo.from} />
                                <InfoRow label="Subject" value={analysisResult.forensicReport.senderInfo.subject} />
                                <div className="grid grid-cols-3 gap-2 py-1">
                                    <span className="col-span-1 font-semibold text-green-300">Auth Checks:</span>
                                    <div className="col-span-2 flex flex-wrap gap-2">
                                        <StatusPill pass={analysisResult.forensicReport.authResults.spf.pass} text="SPF"/>
                                        <StatusPill pass={analysisResult.forensicReport.authResults.dkim.pass} text="DKIM"/>
                                        <StatusPill pass={analysisResult.forensicReport.authResults.dmarc.pass} text="DMARC"/>
                                    </div>
                                </div>
                            </Section>

                            <Section title={`Attachment Analysis (${analysisResult.forensicReport.attachmentAnalysis.count} found)`}>
                                {analysisResult.forensicReport.attachmentAnalysis.count === 0 ? (
                                    <p className="text-green-400">No attachments found.</p>
                                ) : (
                                    <div className="max-h-48 overflow-y-auto pr-2">
                                        {analysisResult.forensicReport.attachmentAnalysis.attachments.map((att, i) => <AttachmentRow key={i} att={att}/>)}
                                    </div>
                                )}
                            </Section>

                            <Section title="Content Analysis">
                                <p>HTML Body Detected: <span className="font-bold">{analysisResult.forensicReport.contentAnalysis.hasHtml ? 'Yes' : 'No'}</span></p>
                                <p>JavaScript Tags: <span className={analysisResult.forensicReport.contentAnalysis.scriptTagCount > 0 ? 'font-bold text-red-500' : ''}>{analysisResult.forensicReport.contentAnalysis.scriptTagCount}</span></p>
                                <p>Inline JS Events: <span className={analysisResult.forensicReport.contentAnalysis.inlineJsCount > 0 ? 'font-bold text-red-500' : ''}>{analysisResult.forensicReport.contentAnalysis.inlineJsCount}</span></p>
                            </Section>

                            <Section title="Link & Reputation Analysis">
                                {analysisResult.forensicReport.linkAnalysis.links.length === 0 ? (
                                    <p>No links found.</p>
                                ) : (
                                    <div className="max-h-60 overflow-y-auto pr-2">
                                        {analysisResult.forensicReport.linkAnalysis.links.map((link, i) => <LinkRow key={i} link={link} />)}
                                    </div>
                                )}
                            </Section>
                        </div>
                    </section>
                )}
            </div>
        </div>
    );
}

export default App;