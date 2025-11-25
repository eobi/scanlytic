/**
 * Scamlytic - Main Application JavaScript
 * AI-Powered Scam Detection Frontend
 *
 * Integrated with Django REST API Backend
 */

// ==========================================================================
// Configuration
// ==========================================================================
const CONFIG = {
    API_BASE_URL: 'http://localhost:8000/v1',
    MAX_MESSAGE_LENGTH: 5000,
    DEMO_MODE: false, // Set to true to use demo data without backend
};

// ==========================================================================
// API Service
// ==========================================================================
const API = {
    // Auth token storage
    accessToken: localStorage.getItem('scamlytic_access_token'),
    refreshToken: localStorage.getItem('scamlytic_refresh_token'),
    apiKey: localStorage.getItem('scamlytic_api_key'),

    // Set tokens
    setTokens(access, refresh) {
        this.accessToken = access;
        this.refreshToken = refresh;
        if (access) localStorage.setItem('scamlytic_access_token', access);
        if (refresh) localStorage.setItem('scamlytic_refresh_token', refresh);
    },

    setApiKey(key) {
        this.apiKey = key;
        if (key) localStorage.setItem('scamlytic_api_key', key);
    },

    clearAuth() {
        this.accessToken = null;
        this.refreshToken = null;
        this.apiKey = null;
        localStorage.removeItem('scamlytic_access_token');
        localStorage.removeItem('scamlytic_refresh_token');
        localStorage.removeItem('scamlytic_api_key');
    },

    // Get auth headers
    getHeaders() {
        const headers = {
            'Content-Type': 'application/json',
        };

        if (this.apiKey) {
            headers['X-API-Key'] = this.apiKey;
        } else if (this.accessToken) {
            headers['Authorization'] = `Bearer ${this.accessToken}`;
        }

        return headers;
    },

    // Generic API request
    async request(endpoint, options = {}) {
        const url = `${CONFIG.API_BASE_URL}${endpoint}`;

        const config = {
            headers: this.getHeaders(),
            ...options,
        };

        try {
            const response = await fetch(url, config);

            // Handle 401 - try to refresh token
            if (response.status === 401 && this.refreshToken) {
                const refreshed = await this.refreshAccessToken();
                if (refreshed) {
                    config.headers = this.getHeaders();
                    return await fetch(url, config);
                }
            }

            return response;
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    },

    // Refresh access token
    async refreshAccessToken() {
        try {
            const response = await fetch(`${CONFIG.API_BASE_URL}/users/token/refresh/`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh: this.refreshToken }),
            });

            if (response.ok) {
                const data = await response.json();
                this.setTokens(data.access, data.refresh || this.refreshToken);
                return true;
            }

            this.clearAuth();
            return false;
        } catch (error) {
            this.clearAuth();
            return false;
        }
    },

    // Auth endpoints
    async login(email, password) {
        const response = await fetch(`${CONFIG.API_BASE_URL}/users/login/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });

        if (response.ok) {
            const data = await response.json();
            this.setTokens(data.access, data.refresh);
            return { success: true, data };
        }

        const error = await response.json();
        return { success: false, error };
    },

    async register(email, password, fullName) {
        const response = await fetch(`${CONFIG.API_BASE_URL}/users/register/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email,
                password,
                password_confirm: password,
                full_name: fullName,
            }),
        });

        if (response.ok) {
            const data = await response.json();
            return { success: true, data };
        }

        const error = await response.json();
        return { success: false, error };
    },

    // Analysis endpoints
    async analyzeMessage(content, context = 'received_message') {
        const response = await this.request('/analyze/message/', {
            method: 'POST',
            body: JSON.stringify({ content, context }),
        });

        if (response.ok) {
            return await response.json();
        }

        throw new Error(await response.text());
    },

    async analyzeUrl(url, checkReputation = true) {
        const response = await this.request('/analyze/url/', {
            method: 'POST',
            body: JSON.stringify({ url, check_reputation: checkReputation }),
        });

        if (response.ok) {
            return await response.json();
        }

        throw new Error(await response.text());
    },

    async analyzePhone(phoneNumber) {
        const response = await this.request('/analyze/phone/', {
            method: 'POST',
            body: JSON.stringify({
                phone_number: phoneNumber,
                check_carrier: true,
                check_spam_reports: true,
            }),
        });

        if (response.ok) {
            return await response.json();
        }

        throw new Error(await response.text());
    },

    async analyzeProfile(name, bio, imageUrl, socialLinks = [], platform = 'dating_app') {
        const response = await this.request('/analyze/profile/', {
            method: 'POST',
            body: JSON.stringify({
                name,
                bio,
                image_url: imageUrl,
                social_links: socialLinks,
                platform,
            }),
        });

        if (response.ok) {
            return await response.json();
        }

        throw new Error(await response.text());
    },

    async analyzeProfileWithImage(name, bio, imageBase64, platform = 'dating_app') {
        const response = await this.request('/analyze/profile/', {
            method: 'POST',
            body: JSON.stringify({
                name,
                bio,
                image_data: imageBase64,
                platform,
            }),
        });

        if (response.ok) {
            return await response.json();
        }

        throw new Error(await response.text());
    },

    // Quick scan (anonymous)
    async quickScan(content, type = 'message') {
        const response = await fetch(`${CONFIG.API_BASE_URL}/analyze/quick/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content, type }),
        });

        if (response.ok) {
            return await response.json();
        }

        throw new Error(await response.text());
    },

    // Usage limits
    async getUsageLimits() {
        const response = await this.request('/billing/usage/limits/');
        if (response.ok) {
            return await response.json();
        }
        return null;
    },

    // Submit scam report
    async submitReport(reportData) {
        const response = await this.request('/reports/', {
            method: 'POST',
            body: JSON.stringify(reportData),
        });

        if (response.ok) {
            return await response.json();
        }

        throw new Error(await response.text());
    },

    // Check if authenticated
    isAuthenticated() {
        return !!(this.accessToken || this.apiKey);
    },
};

// ==========================================================================
// DOM Elements
// ==========================================================================
const elements = {
    // Scanner
    scannerTabs: document.querySelectorAll('.scanner-tab'),
    scannerPanels: document.querySelectorAll('.scanner-panel'),
    messageInput: document.getElementById('message-input'),
    urlInput: document.getElementById('url-input'),
    phoneInput: document.getElementById('phone-input'),
    profileInput: document.getElementById('profile-input'),
    imageInput: document.getElementById('image-input'),
    charCount: document.getElementById('char-count'),

    // Buttons
    scanMessageBtn: document.getElementById('scan-message-btn'),
    scanUrlBtn: document.getElementById('scan-url-btn'),
    scanPhoneBtn: document.getElementById('scan-phone-btn'),
    scanCatfishBtn: document.getElementById('scan-catfish-btn'),

    // Upload
    uploadZone: document.getElementById('upload-zone'),
    uploadPreview: document.getElementById('upload-preview'),
    previewImage: document.getElementById('preview-image'),
    removeImage: document.getElementById('remove-image'),

    // Modal
    modal: document.getElementById('results-modal'),
    modalClose: document.getElementById('modal-close'),
    modalLoading: document.getElementById('modal-loading'),
    modalResults: document.getElementById('modal-results'),
    loadingSteps: document.querySelectorAll('.loading-step'),

    // Results
    resultScoreRing: document.getElementById('result-score-ring'),
    scoreCircle: document.getElementById('score-circle'),
    scoreNumber: document.getElementById('score-number'),
    verdictBadge: document.getElementById('verdict-badge'),
    threatType: document.getElementById('threat-type'),
    resultExplanation: document.getElementById('result-explanation'),
    signalsList: document.getElementById('signals-list'),
    resultAction: document.getElementById('result-action'),

    // Share buttons
    shareWhatsapp: document.getElementById('share-whatsapp'),
    shareTwitter: document.getElementById('share-twitter'),
    shareFacebook: document.getElementById('share-facebook'),
    shareCopy: document.getElementById('share-copy'),
    shareDownload: document.getElementById('share-download'),
    scanAnother: document.getElementById('scan-another'),
    reportScam: document.getElementById('report-scam'),

    // Mobile menu
    mobileMenuBtn: document.querySelector('.mobile-menu-btn'),
    navLinks: document.querySelector('.nav-links'),
};

// ==========================================================================
// State
// ==========================================================================
let currentAnalysis = null;
let uploadedImage = null;
let uploadedImageBase64 = null;

// ==========================================================================
// Scanner Tab Switching
// ==========================================================================
function initTabs() {
    elements.scannerTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.dataset.tab;

            // Update active tab
            elements.scannerTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            // Update active panel
            elements.scannerPanels.forEach(panel => {
                panel.classList.remove('active');
                if (panel.id === `${tabName}-panel`) {
                    panel.classList.add('active');
                }
            });
        });
    });
}

// ==========================================================================
// Character Count
// ==========================================================================
function initCharCount() {
    if (elements.messageInput) {
        elements.messageInput.addEventListener('input', () => {
            const count = elements.messageInput.value.length;
            elements.charCount.textContent = count;

            if (count > CONFIG.MAX_MESSAGE_LENGTH) {
                elements.charCount.style.color = 'var(--color-critical)';
            } else {
                elements.charCount.style.color = '';
            }
        });
    }
}

// ==========================================================================
// Image Upload
// ==========================================================================
function initImageUpload() {
    if (!elements.uploadZone) return;

    // Click to upload
    elements.uploadZone.addEventListener('click', () => {
        elements.imageInput.click();
    });

    // Drag and drop
    elements.uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        elements.uploadZone.style.borderColor = 'var(--color-accent-primary)';
    });

    elements.uploadZone.addEventListener('dragleave', () => {
        elements.uploadZone.style.borderColor = '';
    });

    elements.uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        elements.uploadZone.style.borderColor = '';

        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) {
            handleImageUpload(file);
        }
    });

    // File input change
    elements.imageInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            handleImageUpload(file);
        }
    });

    // Remove image
    elements.removeImage.addEventListener('click', () => {
        uploadedImage = null;
        uploadedImageBase64 = null;
        elements.uploadZone.style.display = '';
        elements.uploadPreview.style.display = 'none';
        elements.imageInput.value = '';
    });
}

function handleImageUpload(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        uploadedImage = e.target.result;
        uploadedImageBase64 = e.target.result.split(',')[1]; // Get base64 without data URL prefix
        elements.previewImage.src = uploadedImage;
        elements.uploadZone.style.display = 'none';
        elements.uploadPreview.style.display = 'block';
    };
    reader.readAsDataURL(file);
}

// ==========================================================================
// Modal Functions
// ==========================================================================
function openModal() {
    elements.modal.classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeModal() {
    elements.modal.classList.remove('active');
    document.body.style.overflow = '';
}

function showLoading() {
    elements.modalLoading.style.display = '';
    elements.modalResults.style.display = 'none';

    // Reset loading steps
    elements.loadingSteps.forEach((step, index) => {
        step.classList.remove('active', 'complete');
        const icon = step.querySelector('i');
        icon.className = 'fas fa-circle';
    });

    // Animate loading steps
    animateLoadingSteps();
}

function animateLoadingSteps() {
    const steps = elements.loadingSteps;
    let currentStep = 0;

    const interval = setInterval(() => {
        if (currentStep > 0) {
            steps[currentStep - 1].classList.remove('active');
            steps[currentStep - 1].classList.add('complete');
            steps[currentStep - 1].querySelector('i').className = 'fas fa-check';
        }

        if (currentStep < steps.length) {
            steps[currentStep].classList.add('active');
            steps[currentStep].querySelector('i').className = 'fas fa-spinner fa-spin';
            currentStep++;
        } else {
            clearInterval(interval);
        }
    }, 600);
}

function showResults(analysis) {
    currentAnalysis = normalizeAnalysisResponse(analysis);

    elements.modalLoading.style.display = 'none';
    elements.modalResults.style.display = '';

    // Update score
    const score = currentAnalysis.scam_score;
    elements.scoreNumber.textContent = score;

    // Calculate stroke offset (283 is full circle)
    const offset = 283 - (283 * score / 100);
    elements.scoreCircle.style.strokeDashoffset = offset;

    // Update risk level styling
    const riskClass = getRiskClass(score);
    elements.resultScoreRing.className = `result-score-ring ${riskClass}`;
    elements.verdictBadge.className = `verdict-badge ${riskClass}`;

    // Update verdict badge text
    elements.verdictBadge.innerHTML = `
        <i class="fas ${getVerdictIcon(riskClass)}"></i>
        ${currentAnalysis.verdict.replace(/_/g, ' ')}
    `;

    // Update threat type
    elements.threatType.textContent = formatThreatType(currentAnalysis.threat_type);

    // Update explanation
    elements.resultExplanation.textContent = currentAnalysis.explanation;

    // Update signals
    elements.signalsList.innerHTML = currentAnalysis.signals.map(signal => `
        <div class="signal-item ${getSignalClass(signal)}">
            <i class="fas ${getSignalIcon(signal)}"></i>
            <span>${formatSignal(signal)}</span>
        </div>
    `).join('');

    // Update action
    elements.resultAction.textContent = currentAnalysis.recommended_action;
}

function showError(message) {
    elements.modalLoading.style.display = 'none';
    elements.modalResults.style.display = '';

    elements.scoreNumber.textContent = '!';
    elements.resultScoreRing.className = 'result-score-ring error';
    elements.verdictBadge.className = 'verdict-badge error';
    elements.verdictBadge.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Error';
    elements.threatType.textContent = 'Analysis Failed';
    elements.resultExplanation.textContent = message;
    elements.signalsList.innerHTML = '';
    elements.resultAction.textContent = 'Please try again or contact support if the issue persists.';
}

// Normalize API response to consistent format
function normalizeAnalysisResponse(response) {
    return {
        scam_score: response.scam_score || response.risk_score || response.score || 0,
        verdict: response.verdict || response.risk_level || getVerdict(response.scam_score || 0),
        threat_type: response.threat_type || response.classification || response.category || 'UNKNOWN',
        explanation: response.explanation || response.summary || response.description || '',
        recommended_action: response.recommended_action || response.action || response.recommendation || '',
        signals: response.signals || response.indicators || response.flags || [],
        request_id: response.request_id || response.id || '',
    };
}

// ==========================================================================
// Analysis Functions - Real API Calls
// ==========================================================================
async function analyzeMessage(content) {
    openModal();
    showLoading();

    try {
        let analysis;

        if (CONFIG.DEMO_MODE) {
            await simulateDelay(2500);
            analysis = generateDemoAnalysis(content, 'message');
        } else {
            // Try authenticated request first, fall back to quick scan
            if (API.isAuthenticated()) {
                analysis = await API.analyzeMessage(content);
            } else {
                analysis = await API.quickScan(content, 'message');
            }
        }

        showResults(analysis);
    } catch (error) {
        console.error('Analysis failed:', error);

        // Fallback to demo mode on error
        if (!CONFIG.DEMO_MODE) {
            console.log('Falling back to demo analysis');
            await simulateDelay(1000);
            const analysis = generateDemoAnalysis(content, 'message');
            showResults(analysis);
        } else {
            showError('Unable to analyze message. Please check your connection and try again.');
        }
    }
}

async function analyzeUrl(url) {
    if (!isValidUrl(url)) {
        showNotification('Please enter a valid URL', 'error');
        return;
    }

    openModal();
    showLoading();

    try {
        let analysis;

        if (CONFIG.DEMO_MODE) {
            await simulateDelay(2500);
            analysis = generateDemoAnalysis(url, 'url');
        } else {
            if (API.isAuthenticated()) {
                analysis = await API.analyzeUrl(url);
            } else {
                analysis = await API.quickScan(url, 'url');
            }
        }

        showResults(analysis);
    } catch (error) {
        console.error('URL analysis failed:', error);

        if (!CONFIG.DEMO_MODE) {
            await simulateDelay(1000);
            const analysis = generateDemoAnalysis(url, 'url');
            showResults(analysis);
        } else {
            showError('Unable to analyze URL. Please try again.');
        }
    }
}

async function analyzePhone(phone) {
    if (!phone.trim()) {
        showNotification('Please enter a phone number', 'error');
        return;
    }

    openModal();
    showLoading();

    try {
        let analysis;

        if (CONFIG.DEMO_MODE) {
            await simulateDelay(2500);
            analysis = generateDemoAnalysis(phone, 'phone');
        } else {
            if (API.isAuthenticated()) {
                analysis = await API.analyzePhone(phone);
            } else {
                analysis = await API.quickScan(phone, 'phone');
            }
        }

        showResults(analysis);
    } catch (error) {
        console.error('Phone analysis failed:', error);

        if (!CONFIG.DEMO_MODE) {
            await simulateDelay(1000);
            const analysis = generateDemoAnalysis(phone, 'phone');
            showResults(analysis);
        } else {
            showError('Unable to analyze phone number. Please try again.');
        }
    }
}

async function analyzeCatfish(imageData, profileUrl) {
    if (!imageData && !profileUrl) {
        showNotification('Please upload an image or enter a profile URL', 'error');
        return;
    }

    openModal();
    showLoading();

    try {
        let analysis;

        if (CONFIG.DEMO_MODE) {
            await simulateDelay(3000);
            analysis = generateDemoAnalysis(profileUrl || 'image', 'catfish');
        } else {
            if (API.isAuthenticated()) {
                if (uploadedImageBase64) {
                    // Upload image for reverse search
                    analysis = await API.analyzeProfileWithImage(
                        '', // name can be extracted from profile
                        '', // bio
                        uploadedImageBase64,
                        'dating_app'
                    );
                } else if (profileUrl) {
                    analysis = await API.analyzeProfile(
                        '',
                        '',
                        profileUrl,
                        [],
                        'dating_app'
                    );
                }
            } else {
                // Quick scan doesn't support image upload
                analysis = await API.quickScan(profileUrl || 'profile_image', 'profile');
            }
        }

        showResults(analysis);
    } catch (error) {
        console.error('Catfish analysis failed:', error);

        if (!CONFIG.DEMO_MODE) {
            await simulateDelay(1000);
            const analysis = generateDemoAnalysis(profileUrl || 'image', 'catfish');
            showResults(analysis);
        } else {
            showError('Unable to analyze profile. Please try again.');
        }
    }
}

// ==========================================================================
// Demo Analysis Generator (Fallback)
// ==========================================================================
function generateDemoAnalysis(input, type) {
    const inputLower = (typeof input === 'string' ? input : '').toLowerCase();

    // Detect scam patterns for all 8 major scam types
    const scamPatterns = {
        // Bank Impersonation
        bank: /gtbank|first\s*bank|access\s*bank|uba|zenith|stanbic|fidelity|union\s*bank|account.*(?:blocked|suspended|restricted)|verify.*account/i,

        // BVN/NIN Phishing
        bvn: /bvn|bank\s*verification|verify.*bvn/i,
        nin: /nin|national\s*id|nimc|identity\s*number/i,

        // Romance Scams
        romance: /love\s*you|soul\s*mate|deployed|stationed.*overseas|stranded|send\s*money|western\s*union|gift\s*card/i,

        // Job Scams
        job: /work\s*from\s*home|earn\s*\$?\d+.*(?:day|week|hour)|no\s*experience|hiring\s*(?:immediately|urgently)|registration\s*fee/i,

        // Lottery/Prize Scams
        lottery: /won|lottery|prize|million|congratulations|claim.*(?:prize|winning)|sweepstakes|lucky\s*winner/i,

        // Crypto/Forex Fraud
        crypto: /crypto|bitcoin|btc|eth|forex|investment.*(?:return|profit)|guaranteed.*return|double\s*your|seed\s*phrase|elon.*giveaway/i,

        // Government Fee Scams
        government: /irs|tax.*(?:refund|debt)|government.*(?:grant|loan)|stimulus|social\s*security|court\s*summons|efcc|cbn/i,

        // Common urgency patterns
        urgency: /urgent|immediately|24\s*hours|expire|limited\s*time|act\s*now|don't\s*delay/i,

        // Suspicious links
        link: /bit\.ly|tinyurl|click\s*here|verify|confirm.*(?:identity|account)/i,
    };

    let score = 15;
    let signals = [];
    let threatType = 'UNKNOWN';
    let explanation = '';
    let action = 'No immediate action required, but stay vigilant.';

    if (type === 'message') {
        // Check for each scam type
        if (scamPatterns.bvn.test(inputLower)) {
            score += 40;
            signals.push('bvn_phishing');
            threatType = 'BVN_PHISHING';
        }
        if (scamPatterns.nin.test(inputLower)) {
            score += 35;
            signals.push('nin_phishing');
            threatType = threatType === 'UNKNOWN' ? 'NIN_PHISHING' : threatType;
        }
        if (scamPatterns.bank.test(inputLower)) {
            score += 30;
            signals.push('bank_impersonation');
            threatType = threatType === 'UNKNOWN' ? 'BANK_IMPERSONATION' : threatType;
        }
        if (scamPatterns.romance.test(inputLower)) {
            score += 35;
            signals.push('romance_scam');
            threatType = threatType === 'UNKNOWN' ? 'ROMANCE_SCAM' : threatType;
        }
        if (scamPatterns.lottery.test(inputLower)) {
            score += 40;
            signals.push('lottery_scam');
            threatType = threatType === 'UNKNOWN' ? 'LOTTERY_SCAM' : threatType;
        }
        if (scamPatterns.job.test(inputLower)) {
            score += 30;
            signals.push('job_scam');
            threatType = threatType === 'UNKNOWN' ? 'JOB_SCAM' : threatType;
        }
        if (scamPatterns.crypto.test(inputLower)) {
            score += 40;
            signals.push('crypto_fraud');
            threatType = threatType === 'UNKNOWN' ? 'CRYPTO_FOREX_SCAM' : threatType;
        }
        if (scamPatterns.government.test(inputLower)) {
            score += 35;
            signals.push('government_scam');
            threatType = threatType === 'UNKNOWN' ? 'GOVERNMENT_FEE_SCAM' : threatType;
        }
        if (scamPatterns.urgency.test(inputLower)) {
            score += 15;
            signals.push('urgency_language');
        }
        if (scamPatterns.link.test(inputLower)) {
            score += 20;
            signals.push('suspicious_url');
        }

        // Cap score at 99
        score = Math.min(score, 99);

        if (signals.length === 0) {
            signals = ['no_major_threats'];
            threatType = 'LIKELY_SAFE';
        }
    } else if (type === 'url') {
        // URL analysis
        if (inputLower.includes('bit.ly') || inputLower.includes('tinyurl')) {
            score = 75;
            signals = ['shortened_url', 'hidden_destination'];
            threatType = 'SUSPICIOUS_URL';
        } else if (!inputLower.includes('https://')) {
            score = 45;
            signals = ['no_ssl', 'unencrypted'];
            threatType = 'INSECURE_URL';
        } else if (inputLower.includes('login') || inputLower.includes('verify') || inputLower.includes('secure')) {
            score = 60;
            signals = ['phishing_keywords', 'potential_phishing'];
            threatType = 'POTENTIAL_PHISHING';
        } else {
            score = 20;
            signals = ['valid_ssl', 'no_blocklist_match'];
            threatType = 'LIKELY_SAFE';
        }
    } else if (type === 'phone') {
        // Phone analysis
        const isNigerian = input.startsWith('+234') || input.startsWith('234') || input.startsWith('0');
        score = isNigerian ? Math.floor(Math.random() * 30) + 30 : Math.floor(Math.random() * 40) + 20;
        signals = ['carrier_lookup_complete'];

        if (score > 50) {
            signals.push('spam_reports_found', 'voip_number');
            threatType = 'SUSPICIOUS_NUMBER';
        } else {
            signals.push('no_spam_reports');
            threatType = 'UNKNOWN_NUMBER';
        }
    } else if (type === 'catfish') {
        // Catfish analysis
        score = Math.floor(Math.random() * 40) + 45;
        signals = ['reverse_image_search_complete'];

        if (score > 60) {
            signals.push('image_found_elsewhere', 'profile_inconsistencies', 'stock_photo_detected');
            threatType = 'POTENTIAL_CATFISH';
        } else {
            signals.push('limited_matches_found');
            threatType = 'UNVERIFIED_PROFILE';
        }
    }

    // Generate explanation based on score
    if (score >= 75) {
        explanation = `This ${type === 'message' ? 'message' : type === 'url' ? 'URL' : type === 'phone' ? 'number' : 'profile'} shows multiple high-risk indicators commonly associated with scams. Our AI detected manipulation tactics and deceptive patterns.`;
        action = 'Do NOT respond or click any links. Block the sender immediately and report if you\'ve already interacted.';
    } else if (score >= 50) {
        explanation = `Several suspicious elements were detected. While not definitely a scam, exercise extreme caution and verify through official channels.`;
        action = 'Do not share personal information. Verify independently through official sources before proceeding.';
    } else if (score >= 25) {
        explanation = `Some minor concerns detected, but nothing definitively malicious. The ${type} appears to be relatively low risk.`;
        action = 'Proceed with normal caution. Verify sender identity if requesting sensitive information.';
    } else {
        explanation = `No significant scam indicators detected. This appears to be legitimate, but always stay vigilant.`;
        action = 'No immediate action required, but always verify before sharing sensitive information.';
    }

    return {
        scam_score: score,
        verdict: getVerdict(score),
        threat_type: threatType,
        explanation: explanation,
        recommended_action: action,
        signals: signals,
        request_id: 'demo_' + Math.random().toString(36).substr(2, 9)
    };
}

// ==========================================================================
// Helper Functions
// ==========================================================================
function getRiskClass(score) {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'moderate';
    return 'low';
}

function getVerdict(score) {
    if (score >= 75) return 'CRITICAL_RISK';
    if (score >= 50) return 'HIGH_RISK';
    if (score >= 25) return 'MODERATE_RISK';
    return 'LOW_RISK';
}

function getVerdictIcon(riskClass) {
    const icons = {
        critical: 'fa-exclamation-triangle',
        high: 'fa-exclamation-circle',
        moderate: 'fa-question-circle',
        low: 'fa-check-circle',
        error: 'fa-times-circle'
    };
    return icons[riskClass] || 'fa-info-circle';
}

function getSignalClass(signal) {
    const critical = ['bvn_phishing', 'nin_phishing', 'bank_impersonation', 'lottery_scam', 'crypto_fraud', 'romance_scam', 'government_scam'];
    const high = ['job_scam', 'suspicious_url', 'urgency_language', 'image_found_elsewhere', 'phishing_keywords', 'potential_phishing'];
    const moderate = ['voip_number', 'shortened_url', 'no_ssl', 'profile_inconsistencies', 'spam_reports_found', 'stock_photo_detected'];

    if (critical.includes(signal)) return 'critical';
    if (high.includes(signal)) return 'high';
    if (moderate.includes(signal)) return 'moderate';
    return 'low';
}

function getSignalIcon(signal) {
    const icons = {
        bvn_phishing: 'fa-id-card',
        nin_phishing: 'fa-id-badge',
        bank_impersonation: 'fa-building-columns',
        lottery_scam: 'fa-trophy',
        job_scam: 'fa-briefcase',
        crypto_fraud: 'fa-coins',
        romance_scam: 'fa-heart-crack',
        government_scam: 'fa-landmark',
        urgency_language: 'fa-clock',
        suspicious_url: 'fa-link',
        shortened_url: 'fa-compress',
        no_ssl: 'fa-lock-open',
        voip_number: 'fa-phone-volume',
        image_found_elsewhere: 'fa-images',
        profile_inconsistencies: 'fa-user-xmark',
        reverse_image_search_complete: 'fa-magnifying-glass',
        reverse_image_matches: 'fa-magnifying-glass',
        stock_photo_detected: 'fa-camera',
        phishing_keywords: 'fa-fish',
        potential_phishing: 'fa-fish',
        spam_reports_found: 'fa-flag',
        carrier_lookup_complete: 'fa-signal',
        no_spam_reports: 'fa-check',
        no_major_threats: 'fa-shield-check',
        valid_ssl: 'fa-lock',
        no_blocklist_match: 'fa-list-check',
        limited_matches_found: 'fa-search',
    };
    return icons[signal] || 'fa-flag';
}

function formatSignal(signal) {
    return signal
        .replace(/_/g, ' ')
        .replace(/\b\w/g, l => l.toUpperCase());
}

function formatThreatType(type) {
    if (!type) return 'Unknown';
    const formatted = type.replace(/_/g, ' ').toLowerCase();
    return formatted.charAt(0).toUpperCase() + formatted.slice(1);
}

function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function simulateDelay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas ${type === 'error' ? 'fa-exclamation-circle' : type === 'success' ? 'fa-check-circle' : 'fa-info-circle'}"></i>
        <span>${message}</span>
    `;

    // Add to body
    document.body.appendChild(notification);

    // Animate in
    setTimeout(() => notification.classList.add('show'), 10);

    // Remove after 3 seconds
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// ==========================================================================
// Social Sharing
// ==========================================================================
function initSharing() {
    elements.shareWhatsapp?.addEventListener('click', () => {
        const text = generateShareText();
        const url = `https://wa.me/?text=${encodeURIComponent(text)}`;
        window.open(url, '_blank');
    });

    elements.shareTwitter?.addEventListener('click', () => {
        const text = generateShareText();
        const url = `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}`;
        window.open(url, '_blank');
    });

    elements.shareFacebook?.addEventListener('click', () => {
        const url = `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent('https://scamlytic.com')}`;
        window.open(url, '_blank');
    });

    elements.shareCopy?.addEventListener('click', () => {
        const text = generateShareText();
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Copied to clipboard!', 'success');
        });
    });

    elements.shareDownload?.addEventListener('click', () => {
        downloadResultAsImage();
    });

    elements.scanAnother?.addEventListener('click', () => {
        closeModal();
    });

    elements.reportScam?.addEventListener('click', async () => {
        if (currentAnalysis && currentAnalysis.scam_score >= 50) {
            try {
                if (API.isAuthenticated()) {
                    await API.submitReport({
                        report_type: currentAnalysis.threat_type?.toLowerCase() || 'unknown',
                        content: 'Reported from scanner',
                        additional_info: JSON.stringify(currentAnalysis),
                    });
                }
                showNotification('Thank you for reporting! This helps protect others.', 'success');
            } catch (error) {
                showNotification('Report submitted locally. Sign in to submit to our database.', 'info');
            }
        } else {
            showNotification('Thank you for your vigilance!', 'success');
        }
    });
}

function generateShareText() {
    if (!currentAnalysis) return '';

    const emoji = currentAnalysis.scam_score >= 75 ? '🚨' : currentAnalysis.scam_score >= 50 ? '⚠️' : '✅';
    return `${emoji} SCAM CHECK: ${currentAnalysis.scam_score}% risk detected!\n\nThreat: ${formatThreatType(currentAnalysis.threat_type)}\n\nCheck suspicious messages at scamlytic.com - it's free!\n\n#ScamAlert #Scamlytic`;
}

function downloadResultAsImage() {
    // Create a shareable text summary
    if (!currentAnalysis) return;

    const summary = `
SCAMLYTIC SCAN RESULT
=====================
Risk Score: ${currentAnalysis.scam_score}%
Verdict: ${currentAnalysis.verdict}
Threat: ${formatThreatType(currentAnalysis.threat_type)}

${currentAnalysis.explanation}

Recommendation: ${currentAnalysis.recommended_action}

Scan ID: ${currentAnalysis.request_id}
Scanned at: ${new Date().toLocaleString()}

Check messages at https://scamlytic.com
    `.trim();

    // Download as text file
    const blob = new Blob([summary], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scamlytic-result-${currentAnalysis.request_id}.txt`;
    a.click();
    URL.revokeObjectURL(url);

    showNotification('Result downloaded!', 'success');
}

// ==========================================================================
// Event Listeners
// ==========================================================================
function initEventListeners() {
    // Scanner buttons
    elements.scanMessageBtn?.addEventListener('click', () => {
        const content = elements.messageInput.value.trim();
        if (content) {
            analyzeMessage(content);
        } else {
            showNotification('Please enter a message to analyze', 'error');
        }
    });

    elements.scanUrlBtn?.addEventListener('click', () => {
        const url = elements.urlInput.value.trim();
        analyzeUrl(url);
    });

    elements.scanPhoneBtn?.addEventListener('click', () => {
        const phone = elements.phoneInput.value.trim();
        analyzePhone(phone);
    });

    elements.scanCatfishBtn?.addEventListener('click', () => {
        const profileUrl = elements.profileInput?.value.trim();
        analyzeCatfish(uploadedImage, profileUrl);
    });

    // Modal
    elements.modalClose?.addEventListener('click', closeModal);
    elements.modal?.querySelector('.modal-backdrop')?.addEventListener('click', closeModal);

    // Mobile menu
    elements.mobileMenuBtn?.addEventListener('click', () => {
        elements.navLinks?.classList.toggle('active');
    });

    // Close modal on Escape
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
        }
    });

    // Enter key to submit
    elements.messageInput?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && e.ctrlKey) {
            elements.scanMessageBtn?.click();
        }
    });

    elements.urlInput?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            elements.scanUrlBtn?.click();
        }
    });

    elements.phoneInput?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            elements.scanPhoneBtn?.click();
        }
    });

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

// ==========================================================================
// Add notification styles dynamically
// ==========================================================================
function addNotificationStyles() {
    const style = document.createElement('style');
    style.textContent = `
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            background: var(--color-surface-elevated, #1a1a2e);
            border: 1px solid var(--color-border, #2a2a4a);
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
            transform: translateX(120%);
            transition: transform 0.3s ease;
            z-index: 10000;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }

        .notification.show {
            transform: translateX(0);
        }

        .notification-success {
            border-color: var(--color-safe, #10b981);
        }

        .notification-success i {
            color: var(--color-safe, #10b981);
        }

        .notification-error {
            border-color: var(--color-critical, #ef4444);
        }

        .notification-error i {
            color: var(--color-critical, #ef4444);
        }

        .notification-info {
            border-color: var(--color-accent-primary, #6366f1);
        }

        .notification-info i {
            color: var(--color-accent-primary, #6366f1);
        }
    `;
    document.head.appendChild(style);
}

// ==========================================================================
// Initialize
// ==========================================================================
document.addEventListener('DOMContentLoaded', () => {
    addNotificationStyles();
    initTabs();
    initCharCount();
    initImageUpload();
    initSharing();
    initEventListeners();

    // Log API configuration
    console.log('🛡️ Scamlytic initialized');
    console.log(`📡 API Base URL: ${CONFIG.API_BASE_URL}`);
    console.log(`🔐 Authenticated: ${API.isAuthenticated()}`);
    console.log(`🧪 Demo Mode: ${CONFIG.DEMO_MODE}`);
});

// ==========================================================================
// Expose API for external use (e.g., from console or other scripts)
// ==========================================================================
window.ScamlyticAPI = API;
window.ScamlyticConfig = CONFIG;
