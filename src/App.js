import React, { useState, useEffect } from 'react';

// --- COMPACT UI COMPONENTS (Watch Dogs Style) ---

const StatusPill = ({ pass, text }) => (
    <span className={`px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
        pass 
            ? 'bg-green-500/20 text-green-400 border border-green-500/50' 
            : 'bg-red-500/20 text-red-400 border border-red-500/50'
    }`}>
        {text}
    </span>
);

const Section = ({ title, children, defaultOpen = true }) => {
    const [isOpen, setIsOpen] = useState(defaultOpen);
    
    return (
        <div className="border-l-2 border-red-500/30 pl-3 mb-3">
            <button 
                onClick={() => setIsOpen(!isOpen)}
                className="w-full flex items-center justify-between text-left text-xs font-bold text-red-400 uppercase tracking-wider mb-2 hover:text-red-300 transition-colors"
            >
                <span className="flex items-center gap-2">
                    <span className="text-red-500">&gt;</span>
                    {title}
                </span>
                <span className="text-red-500/50">{isOpen ? '[-]' : '[+]'}</span>
            </button>
            {isOpen && <div className="text-[11px] space-y-1">{children}</div>}
        </div>
    );
};

const InfoRow = ({ label, value }) => (
    <div className="flex gap-2 py-0.5 text-[11px]">
        <span className="text-red-400 min-w-[80px] font-bold">{label}:</span>
        <span className="text-gray-300 break-words flex-1">{value}</span>
    </div>
);

const LinkRow = ({ link }) => {
    let reputationColor = 'text-gray-500';
    let reputationIcon = '?';
    let reputationText = 'N/A';
    
    if (link.reputation) {
        if (link.reputation.status === 'Found') {
            reputationText = `VT: ${link.reputation.score}`;
            if (link.reputation.isMalicious) {
                reputationColor = 'text-red-400';
                reputationIcon = '!';
            } else {
                reputationColor = 'text-green-400';
                reputationIcon = '✓';
            }
        } else {
            reputationText = link.reputation.status;
            reputationColor = 'text-yellow-400';
            reputationIcon = '-';
        }
    }
    
    return (
        <div className="border-t border-red-900/30 py-1.5 hover:bg-red-950/20 px-1 transition-all">
            <div className="flex items-center justify-between gap-2">
                <span className="text-[10px] text-red-400 truncate flex-1">{link.domain}</span>
                <div className="flex items-center gap-1">
                    <span className={`text-[9px] font-mono ${reputationColor}`}>{reputationText}</span>
                    <span className={`text-[10px] font-bold ${reputationColor}`}>[{reputationIcon}]</span>
                </div>
            </div>
            <p className="text-[9px] text-gray-500 truncate mt-0.5" title={link.url}>{link.url}</p>
        </div>
    );
};

const AttachmentRow = ({ att }) => (
    <div className="border-t border-red-900/30 py-1.5 hover:bg-red-950/20 px-1 transition-all">
        <div className="flex justify-between items-center gap-2">
            <p className="text-[10px] text-red-400 truncate flex-1">{att.filename}</p>
            <StatusPill pass={!att.isDangerous} text={att.isDangerous ? 'DANGER' : 'SAFE'}/>
        </div>
        <div className="text-[9px] text-gray-500 mt-0.5">
            <p className="truncate">SHA: {att.sha256}</p>
        </div>
    </div>
);

// Main App
function App() {
    const [selectedFile, setSelectedFile] = useState(null);
    const [analysisResult, setAnalysisResult] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [loadingText, setLoadingText] = useState('INIT...');
    
    const loadingMessages = [
        'PARSING...', 
        'SCANNING...', 
        'HASHING...', 
        'QUERYING...', 
        'ANALYZING...', 
        'COMPILING...'
    ];
    
    useEffect(() => {
        let interval;
        if (isLoading) {
            let i = 0;
            interval = setInterval(() => {
                i = (i + 1) % loadingMessages.length;
                setLoadingText(loadingMessages[i]);
            }, 600);
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
            setError('ERR: INVALID FILE TYPE');
        }
    };

    const handleSubmit = async () => {
        if (!selectedFile) return;

        setIsLoading(true);
        setAnalysisResult(null);
        setError('');

        const formData = new FormData();
        formData.append('emlfile', selectedFile);

        try {
            const response = await fetch('http://localhost:3001/api/analyze', {
                method: 'POST',
                body: formData,
            });
            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'SERVER ERROR');
            }
            const result = await response.json();
            
            const verdict = result.aiVerdict.verdict?.toLowerCase();
            result.displayVerdict = verdict === 'ham' ? 'SAFE' : 'THREAT';
            result.verdictClass = verdict === 'ham' ? 'safe' : 'threat';
            
            setAnalysisResult(result);
        } catch (err) {
            setError(`ERR: ${err.message}`);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="min-h-screen p-4 font-mono">
            <div className="scanline-overlay"></div>
            <div className="max-w-5xl mx-auto">
                
                {/* Compact Header */}
                <header className="mb-4 border border-red-500/30 bg-black/60 backdrop-blur-sm p-4">
                    <div className="flex items-center justify-between">
                        <div>
                            <div className="flex items-center gap-2 mb-1">
                                <span className="w-2 h-2 bg-red-400 rounded-full animate-pulse"></span>
                                <h1 className="text-xl font-bold text-red-400 tracking-wider" style={{ fontFamily: 'Orbitron, monospace' }}>
                                    EML_ANALYZER
                                </h1>
                            </div>
                            <p className="text-[9px] text-red-600 uppercase tracking-widest">
                                v4.0 • AI THREAT DETECTION SYSTEM
                            </p>
                        </div>
                        <div className="text-right text-[9px] text-red-600">
                            <div>STATUS: ONLINE</div>
                            <div>MODE: ACTIVE</div>
                        </div>
                    </div>
                </header>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    
                    {/* Left Panel - Upload & Controls */}
                    <div className="lg:col-span-1 space-y-4">
                        
                        {/* File Upload */}
                        <div className="border border-red-500/30 bg-black/60 backdrop-blur-sm p-4">
                            <div className="text-[10px] text-red-400 uppercase tracking-wider mb-3 font-bold">
                                [ FILE UPLOAD ]
                            </div>
                            <label 
                                htmlFor="file-input" 
                                className="cursor-pointer block border border-dashed border-red-700/50 p-6 hover:border-red-500 hover:bg-red-950/20 transition-all text-center group"
                            >
                                <div className="text-red-500 mb-2 text-2xl group-hover:scale-110 transition-transform">
                                    {selectedFile ? '✓' : '↑'}
                                </div>
                                {selectedFile ? (
                                    <div className="text-[10px]">
                                        <div className="text-green-400 font-bold mb-1">READY</div>
                                        <div className="text-gray-400 truncate">{selectedFile.name}</div>
                                    </div>
                                ) : (
                                    <div className="text-[10px] text-gray-400">
                                        DROP .EML FILE
                                    </div>
                                )}
                            </label>
                            <input 
                                type="file" 
                                id="file-input" 
                                className="hidden" 
                                accept=".eml" 
                                onChange={handleFileChange} 
                            />
                        </div>

                        {/* Execute Button */}
                        <button 
                            onClick={handleSubmit} 
                            disabled={!selectedFile || isLoading} 
                            className="w-full bg-red-500/10 border border-red-500/50 text-red-400 font-bold py-3 px-4 hover:bg-red-500/20 hover:border-red-400 disabled:opacity-30 disabled:cursor-not-allowed transition-all text-sm uppercase tracking-wider disabled:hover:bg-red-500/10"
                        >
                            {isLoading ? `${loadingText}` : '[ EXECUTE SCAN ]'}
                        </button>

                        {/* Error Display */}
                        {error && (
                            <div className="border border-red-500/50 bg-red-950/20 p-3 text-red-400 text-[10px] uppercase tracking-wider animate-pulse">
                                {error}
                            </div>
                        )}

                        {/* Loading Indicator */}
                        {isLoading && (
                            <div className="border border-red-500/30 bg-black/60 p-3">
                                <div className="flex items-center gap-2 text-red-400 text-[10px]">
                                    <div className="w-1.5 h-1.5 bg-red-400 rounded-full animate-ping"></div>
                                    <span className="uppercase tracking-wider">{loadingText}</span>
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Right Panel - Results */}
                    <div className="lg:col-span-2">
                        {analysisResult ? (
                            <div className="border border-red-500/30 bg-black/60 backdrop-blur-sm p-4 space-y-4">
                                
                                {/* Verdict Banner */}
                                <div className={`border-2 p-4 text-center ${
                                    analysisResult.verdictClass === 'safe'
                                        ? 'border-green-500/50 bg-green-950/20'
                                        : 'border-red-500/50 bg-red-950/20'
                                }`}>
                                    <div className="text-[9px] text-gray-400 uppercase tracking-widest mb-1">
                                        AI VERDICT
                                    </div>
                                    <h2 className={`text-3xl font-bold tracking-wider ${
                                        analysisResult.verdictClass === 'safe' ? 'text-green-400' : 'text-red-400'
                                    }`} style={{ fontFamily: 'Orbitron, monospace' }}>
                                        {analysisResult.displayVerdict}
                                    </h2>
                                    <div className="text-[9px] text-gray-500 mt-1">
                                        CONF: {(analysisResult.aiVerdict.confidence * 100).toFixed(0)}%
                                    </div>
                                </div>

                                {/* Forensic Data */}
                                <div className="text-[10px] text-red-400 uppercase tracking-wider mb-2 font-bold border-b border-red-900/50 pb-1">
                                    [ FORENSIC REPORT ]
                                </div>

                                {/* Single Column Layout - FIXED */}
                                <div className="space-y-3">
                                    
                                    <Section title="Header Data" defaultOpen={true}>
                                        <InfoRow label="FROM" value={analysisResult.forensicReport.senderInfo.from} />
                                        <InfoRow label="TO" value={analysisResult.forensicReport.senderInfo.to} />
                                        <InfoRow label="SUBJECT" value={analysisResult.forensicReport.senderInfo.subject} />
                                        <div className="flex gap-1 mt-2">
                                            <StatusPill pass={analysisResult.forensicReport.authResults.spf.pass} text="SPF"/>
                                            <StatusPill pass={analysisResult.forensicReport.authResults.dkim.pass} text="DKIM"/>
                                            <StatusPill pass={analysisResult.forensicReport.authResults.dmarc.pass} text="DMARC"/>
                                        </div>
                                    </Section>

                                    <Section title="Content Scan" defaultOpen={true}>
                                        <InfoRow label="HTML" value={analysisResult.forensicReport.contentAnalysis.hasHtml ? 'YES' : 'NO'} />
                                        <InfoRow label="JS TAGS" value={analysisResult.forensicReport.contentAnalysis.scriptTagCount} />
                                        <InfoRow label="INLINE JS" value={analysisResult.forensicReport.contentAnalysis.inlineJsCount} />
                                    </Section>

                                    <Section title={`Attachments [${analysisResult.forensicReport.attachmentAnalysis.count}]`} defaultOpen={false}>
                                        {analysisResult.forensicReport.attachmentAnalysis.count === 0 ? (
                                            <p className="text-gray-400 text-[10px]">NONE</p>
                                        ) : (
                                            <div className="max-h-40 overflow-y-auto pr-1 space-y-1">
                                                {analysisResult.forensicReport.attachmentAnalysis.attachments.map((att, i) => 
                                                    <AttachmentRow key={i} att={att}/>
                                                )}
                                            </div>
                                        )}
                                    </Section>

                                    <Section title={`Links [${analysisResult.forensicReport.linkAnalysis.links.length}]`} defaultOpen={false}>
                                        {analysisResult.forensicReport.linkAnalysis.links.length === 0 ? (
                                            <p className="text-gray-400 text-[10px]">NONE</p>
                                        ) : (
                                            <div className="max-h-40 overflow-y-auto pr-1 space-y-1">
                                                {analysisResult.forensicReport.linkAnalysis.links.map((link, i) => 
                                                    <LinkRow key={i} link={link} />
                                                )}
                                            </div>
                                        )}
                                    </Section>
                                </div>
                            </div>
                        ) : (
                            <div className="border border-red-500/30 bg-black/60 backdrop-blur-sm p-12 text-center">
                                <div className="text-red-600/30 text-5xl mb-4">◈</div>
                                <p className="text-red-600/50 text-xs uppercase tracking-widest">
                                    AWAITING INPUT
                                </p>
                            </div>
                        )}
                    </div>
                </div>

                {/* Footer */}
                <footer className="mt-4 text-center text-red-900 text-[8px] uppercase tracking-widest">
                    <p>CTOS v4.0 • AI POWERED • REAL-TIME THREAT INTEL</p>
                </footer>
            </div>
        </div>
    );
}

export default App;