import React, { useState } from 'react';

// --- SUB-COMPONENTS FOR THE FORENSIC REPORT ---

// Displays a single piece of header information (e.g., "From", "Subject")
const InfoRow = ({ label, value }) => (
    <div className="flex flex-col sm:flex-row sm:justify-between border-t border-gray-100 py-2 px-1">
        <span className="text-sm font-semibold text-gray-500">{label}</span>
        <span className="text-sm text-gray-800 text-left sm:text-right break-all">{value}</span>
    </div>
);

// Displays the analysis of the email's code (HTML, CSS, JS)
const CodeAnalysisCard = ({ analysis }) => {
    if (!analysis) return null;
    const { hasHtml, scriptTagCount, styleTagCount, inlineJsCount, isSuspicious } = analysis;

    if (!hasHtml) {
        return (
            <div className="mt-4 p-4 bg-gray-50 rounded-lg">
                <h4 className="font-bold text-gray-700">Content Analysis</h4>
                <p className="text-sm text-gray-600 mt-2">This is a plain text email with no embedded code.</p>
            </div>
        );
    }

    return (
        <div className="mt-4 p-4 bg-gray-50 rounded-lg">
            <h4 className="font-bold text-gray-700">Content Analysis</h4>
            <div className="mt-2 space-y-2">
                <div className={`flex items-center p-2 rounded-md ${isSuspicious ? 'bg-yellow-100' : 'bg-green-100'}`}>
                    <span className={`text-xl ${isSuspicious ? 'text-yellow-600' : 'text-green-600'}`}>
                        {isSuspicious ? '⚠️' : '✓'}
                    </span>
                    <p className={`ml-3 font-semibold ${isSuspicious ? 'text-yellow-800' : 'text-green-800'}`}>
                        {isSuspicious ? 'Potentially Risky Content Detected' : 'No Suspicious Active Content Found'}
                    </p>
                </div>
                <ul className="text-xs text-gray-600 list-disc list-inside pl-2 space-y-1">
                    <li>Contains HTML for formatting.</li>
                    <li>{styleTagCount} CSS style block(s) found.</li>
                    <li><span className={scriptTagCount > 0 ? 'font-bold text-red-600' : ''}>{scriptTagCount} JavaScript &lt;script&gt; tag(s) found.</span></li>
                    <li><span className={inlineJsCount > 0 ? 'font-bold text-red-600' : ''}>{inlineJsCount} inline JavaScript event(s) found (e.g., onclick).</span></li>
                </ul>
            </div>
        </div>
    );
};

// Displays the detailed list of all links and their verification status
const LinkAnalysisCard = ({ analysis }) => {
    if (!analysis) return null;

    const getStatusPill = (status) => {
        if (status.includes('Verified Safe')) {
            return <span className="text-xs font-bold bg-green-200 text-green-800 rounded-full px-2 py-1">Verified Safe</span>;
        }
        if (status.includes('Suspicious')) {
            return <span className="text-xs font-bold bg-red-200 text-red-800 rounded-full px-2 py-1">Suspicious</span>;
        }
        return <span className="text-xs font-bold bg-yellow-200 text-yellow-800 rounded-full px-2 py-1">Unverified</span>;
    };

    return (
        <div className="mt-4 p-4 bg-gray-50 rounded-lg">
            <h4 className="font-bold text-gray-700">Link Analysis</h4>
            <p className="text-xs text-gray-500 mt-1">{analysis.verificationStatus || analysis.status}</p>
            
            {analysis.links && analysis.links.length > 0 && (
                <div className="mt-3 max-h-60 overflow-y-auto pr-2">
                    {analysis.links.map((link, index) => (
                        <div key={index} className="border-t border-gray-200 py-2">
                            <div className="flex items-center justify-between">
                                <span className="text-sm font-semibold text-gray-800">{link.domain}</span>
                                {getStatusPill(link.status)}
                            </div>
                            <p className="text-xs text-blue-600 break-all mt-1" title={link.url}>
                                {link.url}
                            </p>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};


// The main App component
function App() {
    const [selectedFile, setSelectedFile] = useState(null);
    const [analysisResult, setAnalysisResult] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const handleFileChange = (event) => {
        const file = event.target.files[0];
        if (file && file.name.toLowerCase().endsWith('.eml')) {
            setSelectedFile(file);
            setAnalysisResult(null);
            setError('');
        } else {
            setSelectedFile(null);
            setError('Please select a valid .eml file.');
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
                throw new Error(errData.error || 'The server returned an error.');
            }
            const result = await response.json();
            
            // Normalize the AI verdict for display
            const verdict = result.aiVerdict.verdict?.toLowerCase();
            result.displayVerdict = verdict === 'ham' 
                ? 'Safe' 
                : (verdict === 'phishing' || verdict === 'spam' 
                    ? 'Potentially Malicious' 
                    : 'Unknown');
            
            setAnalysisResult(result);
        } catch (err) {
            setError(err.message || 'An unknown error occurred.');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="bg-gray-100 min-h-screen flex items-center justify-center p-4 font-sans">
            <div className="max-w-2xl w-full space-y-8">
                <header className="text-center">
                    <h1 className="text-4xl font-bold text-gray-800">Email Forensic Analyzer</h1>
                    <p className="text-lg text-gray-600 mt-2">Upload an email file to generate a detailed security report.</p>
                </header>

                <main className="bg-white p-8 rounded-2xl shadow-lg">
                    <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center transition hover:border-blue-500">
                        <input type="file" id="file-input" className="hidden" accept=".eml" onChange={handleFileChange} />
                        <label htmlFor="file-input" className="cursor-pointer font-medium text-blue-600 hover:text-blue-700">
                            {selectedFile ? `Selected: ${selectedFile.name}` : 'Click to select an .eml file'}
                        </label>
                        {error && <p className="text-red-600 text-sm mt-3">{error}</p>}
                    </div>
                    <div className="mt-6">
                        <button onClick={handleSubmit} disabled={!selectedFile || isLoading} className="w-full bg-blue-600 text-white font-semibold py-3 px-8 rounded-lg hover:bg-blue-700 transition-all duration-300 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center justify-center">
                           {isLoading ? 'Analyzing...' : 'Generate Report'}
                        </button>
                    </div>
                </main>

                {analysisResult && (
                    <section className="bg-white p-6 rounded-2xl shadow-lg">
                        {/* AI Verdict */}
                        <div className={`p-4 rounded-lg ${analysisResult.displayVerdict === 'Safe' ? 'bg-green-100' : 'bg-red-100'}`}>
                            <h3 className={`text-2xl font-bold ${analysisResult.displayVerdict === 'Safe' ? 'text-green-800' : 'text-red-800'}`}>
                                AI Verdict: {analysisResult.displayVerdict}
                            </h3>
                        </div>
                        
                        {/* Forensic Report */}
                        <div className="mt-6">
                            <h3 className="text-xl font-bold text-gray-800">Forensic Report</h3>
                            <div className="mt-2 p-4 border border-gray-200 rounded-lg">
                                <h4 className="font-bold text-gray-700 mb-2">Header Information</h4>
                                <InfoRow label="From" value={analysisResult.forensicReport.senderInfo.from} />
                                <InfoRow label="To" value={analysisResult.forensicReport.senderInfo.to} />
                                <InfoRow label="Subject" value={analysisResult.forensicReport.senderInfo.subject} />
                                <InfoRow label="Date" value={new Date(analysisResult.forensicReport.senderInfo.date).toLocaleString()} />
                                
                                <CodeAnalysisCard analysis={analysisResult.forensicReport.contentAnalysis} />
                                
                                <LinkAnalysisCard analysis={analysisResult.forensicReport.linkAnalysis} />
                            </div>
                        </div>
                    </section>
                )}
            </div>
        </div>
    );
}

export default App;