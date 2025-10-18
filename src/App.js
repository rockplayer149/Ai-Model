import React, { useState } from 'react';

/**
 * A component that renders the detailed URL analysis report,
 * now including the sender verification status.
 */
const UrlAnalysisReport = ({ analysis }) => {
    if (!analysis || !analysis.containsUrls) {
        return null;
    }

    const isSuspicious = analysis.isSuspicious;
    const containerClasses = isSuspicious 
        ? "mt-6 p-4 border-l-4 border-yellow-500 bg-yellow-50 rounded-r-lg" 
        : "mt-6 p-4 border-l-4 border-green-500 bg-green-50 rounded-r-lg";
    const titleClasses = isSuspicious ? "text-lg font-bold text-yellow-800" : "text-lg font-bold text-green-800";
    const textClasses = isSuspicious ? "text-sm text-yellow-700" : "text-sm text-green-700";

    // Create a colored "pill" based on the verification status
    let verificationPill = null;
    if (analysis.verificationStatus) {
        if (analysis.verificationStatus.includes('SUCCESS')) {
            verificationPill = <span className="text-xs font-bold bg-green-200 text-green-800 rounded-full px-2 py-1">Verified</span>;
        } else if (analysis.verificationStatus.includes('FAILED')) {
            verificationPill = <span className="text-xs font-bold bg-red-200 text-red-800 rounded-full px-2 py-1">Unverified</span>;
        } else if (analysis.verificationStatus.includes('local database')) {
             verificationPill = <span className="text-xs font-bold bg-blue-200 text-blue-800 rounded-full px-2 py-1">DB Match</span>;
        }
    }

    return (
        <div className={containerClasses}>
            <h4 className={titleClasses}>
                {isSuspicious ? 'URL Warning' : 'URL Analysis: Safe'}
            </h4>
            
            {/* Display the sender verification status */}
            {analysis.verificationStatus && (
                <div className="mt-2 text-xs text-gray-600 flex items-center gap-2">
                    {verificationPill}
                    <span>{analysis.verificationStatus}</span>
                </div>
            )}

            <p className={`mt-2 pt-2 border-t border-gray-200 ${textClasses}`}>{analysis.reason}</p>
            
            {isSuspicious && analysis.suspiciousLinks.length > 0 && (
                 <div className="mt-4 space-y-3">
                    {analysis.suspiciousLinks.map((link, index) => (
                        <div key={index} className="text-sm border-t border-yellow-200 pt-2">
                            <p>
                                A link points to the unexpected domain: <span className="font-semibold text-red-700">{link.domain}</span>.
                            </p>
                            <p className="text-xs text-gray-600 mt-1">{link.verification}</p>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};


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
            
            const verdict = result.verdict?.toLowerCase();
            result.displayVerdict = verdict === 'ham' 
                ? 'Safe' 
                : (verdict === 'phishing' || verdict === 'spam' 
                    ? 'Potentially Malicious' 
                    : 'Unknown');
            
            setAnalysisResult(result);

        } catch (err) {
            setError(err.message || 'An unknown error occurred during analysis.');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="bg-gray-100 min-h-screen flex items-center justify-center p-4 font-sans">
            <div className="max-w-2xl w-full space-y-8">
                <header className="text-center">
                    <h1 className="text-4xl font-bold text-gray-800">Email Analyzer</h1>
                    <p className="text-lg text-gray-600 mt-2">Check an email for threats and analyze its links.</p>
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
                        <button 
                            onClick={handleSubmit} 
                            disabled={!selectedFile || isLoading} 
                            className="w-full bg-blue-600 text-white font-semibold py-3 px-8 rounded-lg hover:bg-blue-700 transition-all duration-300 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center justify-center"
                        >
                            {isLoading ? (
                                <>
                                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                    </svg>
                                    Analyzing...
                                </>
                            ) : 'Analyze Email'}
                        </button>
                    </div>
                </main>

                {analysisResult && (
                    <section className="bg-white p-6 rounded-2xl shadow-lg">
                        <div className={`p-4 rounded-lg ${analysisResult.displayVerdict === 'Safe' ? 'bg-green-100' : 'bg-red-100'}`}>
                            <h3 className={`text-2xl font-bold ${analysisResult.displayVerdict === 'Safe' ? 'text-green-800' : 'text-red-800'}`}>
                                AI Verdict: {analysisResult.displayVerdict}
                            </h3>
                        </div>
                        
                        <UrlAnalysisReport analysis={analysisResult.urlAnalysis} />
                    </section>
                )}
            </div>
        </div>
    );
}

export default App;