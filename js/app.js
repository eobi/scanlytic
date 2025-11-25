/**
 * Scamlytic - Main Application JavaScript
 * AI-Powered Scam Detection Frontend
 */

// ==========================================================================
// Configuration
// ==========================================================================
const CONFIG = {
    API_BASE_URL: 'https://api.scamlytic.com/v1',
    MAX_MESSAGE_LENGTH: 5000,
    ANALYSIS_DELAY: 2500, // Simulated delay for demo
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
        elements.uploadZone.style.display = '';
        elements.uploadPreview.style.display = 'none';
        elements.imageInput.value = '';
    });
}

function handleImageUpload(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        uploadedImage = e.target.result;
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
    currentAnalysis = analysis;

    elements.modalLoading.style.display = 'none';
    elements.modalResults.style.display = '';

    // Update score
    const score = analysis.scam_score;
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
        ${analysis.verdict.replace('_', ' ')}
    `;

    // Update threat type
    elements.threatType.textContent = formatThreatType(analysis.threat_type);

    // Update explanation
    elements.resultExplanation.textContent = analysis.explanation;

    // Update signals
    elements.signalsList.innerHTML = analysis.signals.map(signal => `
        <div class="signal-item ${getSignalClass(signal)}">
            <i class="fas ${getSignalIcon(signal)}"></i>
            <span>${formatSignal(signal)}</span>
        </div>
    `).join('');

    // Update action
    elements.resultAction.textContent = analysis.recommended_action;
}

// ==========================================================================
// Analysis Functions
// ==========================================================================
async function analyzeMessage(content) {
    openModal();
    showLoading();

    // Simulate API call (in production, this would be a real API call)
    await simulateDelay(CONFIG.ANALYSIS_DELAY);

    // Demo analysis result
    const analysis = generateDemoAnalysis(content, 'message');
    showResults(analysis);
}

async function analyzeUrl(url) {
    if (!isValidUrl(url)) {
        showNotification('Please enter a valid URL', 'error');
        return;
    }

    openModal();
    showLoading();

    await simulateDelay(CONFIG.ANALYSIS_DELAY);

    const analysis = generateDemoAnalysis(url, 'url');
    showResults(analysis);
}

async function analyzePhone(phone) {
    if (!phone.trim()) {
        showNotification('Please enter a phone number', 'error');
        return;
    }

    openModal();
    showLoading();

    await simulateDelay(CONFIG.ANALYSIS_DELAY);

    const analysis = generateDemoAnalysis(phone, 'phone');
    showResults(analysis);
}

async function analyzeCatfish(imageData, profileUrl) {
    if (!imageData && !profileUrl) {
        showNotification('Please upload an image or enter a profile URL', 'error');
        return;
    }

    openModal();
    showLoading();

    await simulateDelay(CONFIG.ANALYSIS_DELAY);

    const analysis = generateDemoAnalysis(profileUrl || 'image', 'catfish');
    showResults(analysis);
}

// ==========================================================================
// Demo Analysis Generator
// ==========================================================================
function generateDemoAnalysis(input, type) {
    const inputLower = (typeof input === 'string' ? input : '').toLowerCase();

    // Detect scam patterns
    const scamPatterns = {
        bvn: /bvn|bank verification/i,
        nin: /nin|national id|identity/i,
        bank: /gtbank|first bank|access bank|uba|zenith|account.*blocked|suspended/i,
        lottery: /won|lottery|prize|million|congratulations/i,
        job: /job offer|vacancy|hiring|remote work.*\$\d+/i,
        crypto: /crypto|bitcoin|forex|investment.*return/i,
        urgency: /urgent|immediately|24 hours|expire|limited time/i,
        link: /bit\.ly|tinyurl|click here|verify|confirm/i,
    };

    let score = 15;
    let signals = [];
    let threatType = 'UNKNOWN';
    let explanation = '';
    let action = 'No immediate action required, but stay vigilant.';

    if (type === 'message') {
        // Check for scam patterns
        if (scamPatterns.bvn.test(inputLower)) {
            score += 35;
            signals.push('bvn_phishing');
            threatType = 'BVN_PHISHING';
        }
        if (scamPatterns.nin.test(inputLower)) {
            score += 30;
            signals.push('nin_phishing');
            threatType = 'NIN_PHISHING';
        }
        if (scamPatterns.bank.test(inputLower)) {
            score += 25;
            signals.push('bank_impersonation');
            threatType = threatType === 'UNKNOWN' ? 'BANK_IMPERSONATION' : threatType;
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
            score += 35;
            signals.push('crypto_fraud');
            threatType = threatType === 'UNKNOWN' ? 'CRYPTO_SCAM' : threatType;
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
        } else {
            score = 20;
            signals = ['valid_ssl', 'no_blocklist_match'];
            threatType = 'LIKELY_SAFE';
        }
    } else if (type === 'phone') {
        // Phone analysis
        score = Math.floor(Math.random() * 40) + 20;
        signals = ['voip_number', 'recently_registered'];
        threatType = score > 50 ? 'SUSPICIOUS_NUMBER' : 'UNKNOWN_NUMBER';
    } else if (type === 'catfish') {
        // Catfish analysis
        score = Math.floor(Math.random() * 50) + 40;
        signals = ['image_found_elsewhere', 'profile_inconsistencies', 'reverse_image_matches'];
        threatType = 'POTENTIAL_CATFISH';
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
        request_id: 'req_' + Math.random().toString(36).substr(2, 9)
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
        low: 'fa-check-circle'
    };
    return icons[riskClass] || 'fa-info-circle';
}

function getSignalClass(signal) {
    const critical = ['bvn_phishing', 'nin_phishing', 'bank_impersonation', 'lottery_scam', 'crypto_fraud'];
    const high = ['job_scam', 'suspicious_url', 'urgency_language', 'image_found_elsewhere'];
    const moderate = ['voip_number', 'shortened_url', 'no_ssl', 'profile_inconsistencies'];

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
        urgency_language: 'fa-clock',
        suspicious_url: 'fa-link',
        shortened_url: 'fa-compress',
        no_ssl: 'fa-lock-open',
        voip_number: 'fa-phone-volume',
        image_found_elsewhere: 'fa-images',
        profile_inconsistencies: 'fa-user-xmark',
        reverse_image_matches: 'fa-magnifying-glass',
        no_major_threats: 'fa-shield-check',
        valid_ssl: 'fa-lock',
        no_blocklist_match: 'fa-list-check',
    };
    return icons[signal] || 'fa-flag';
}

function formatSignal(signal) {
    return signal
        .replace(/_/g, ' ')
        .replace(/\b\w/g, l => l.toUpperCase());
}

function formatThreatType(type) {
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
    // Simple notification (could be enhanced with a proper notification system)
    alert(message);
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

    elements.reportScam?.addEventListener('click', () => {
        showNotification('Thank you for reporting! This helps protect others.', 'success');
    });
}

function generateShareText() {
    if (!currentAnalysis) return '';

    const emoji = currentAnalysis.scam_score >= 75 ? '🚨' : currentAnalysis.scam_score >= 50 ? '⚠️' : '✅';
    return `${emoji} SCAM CHECK: ${currentAnalysis.scam_score}% risk detected!\n\nThreat: ${formatThreatType(currentAnalysis.threat_type)}\n\nCheck suspicious messages at scamlytic.com - it's free!\n\n#ScamAlert #Scamlytic`;
}

function downloadResultAsImage() {
    // In production, this would use html2canvas or similar
    showNotification('Screenshot feature coming soon!', 'info');
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
// Initialize
// ==========================================================================
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initCharCount();
    initImageUpload();
    initSharing();
    initEventListeners();

    console.log('🛡️ Scamlytic initialized');
});
