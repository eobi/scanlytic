/**
 * Scamlytic - Developers Page JavaScript
 */

// ==========================================================================
// DOM Elements
// ==========================================================================
const elements = {
    codeTabs: document.querySelectorAll('.code-tab'),
    codeBlocks: document.querySelectorAll('.code-block[data-lang]'),
    copyCodeBtn: document.querySelector('.copy-code-btn'),
    copyBtns: document.querySelectorAll('.copy-btn'),

    // Signup form
    signupForm: document.getElementById('signup-form'),
    signupSuccess: document.getElementById('signup-success'),
    planSelect: document.getElementById('signup-plan'),
    cardDetails: document.getElementById('card-details'),
    copyApiKey: document.getElementById('copy-api-key'),
    generatedApiKey: document.getElementById('generated-api-key'),

    // Mobile menu
    mobileMenuBtn: document.querySelector('.mobile-menu-btn'),
    navLinks: document.querySelector('.nav-links'),
};

// ==========================================================================
// Code Tab Switching
// ==========================================================================
function initCodeTabs() {
    elements.codeTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const lang = tab.dataset.lang;

            // Update active tab
            elements.codeTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            // Update active code block
            elements.codeBlocks.forEach(block => {
                block.classList.remove('active');
                if (block.dataset.lang === lang) {
                    block.classList.add('active');
                }
            });
        });
    });
}

// ==========================================================================
// Copy Code Functionality
// ==========================================================================
function initCopyCode() {
    // Copy main code block
    elements.copyCodeBtn?.addEventListener('click', () => {
        const activeBlock = document.querySelector('.code-block.active[data-lang]');
        if (activeBlock) {
            copyToClipboard(activeBlock.textContent);
            showCopyFeedback(elements.copyCodeBtn);
        }
    });

    // Copy buttons throughout the page
    elements.copyBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const parent = btn.closest('.code-snippet, .api-key-display');
            const code = parent?.querySelector('code');
            if (code) {
                copyToClipboard(code.textContent);
                showCopyFeedback(btn);
            }
        });
    });
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text.trim()).catch(err => {
        console.error('Failed to copy:', err);
    });
}

function showCopyFeedback(btn) {
    const originalIcon = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-check"></i>';
    btn.style.color = 'var(--color-low)';

    setTimeout(() => {
        btn.innerHTML = originalIcon;
        btn.style.color = '';
    }, 2000);
}

// ==========================================================================
// Signup Form
// ==========================================================================
function initSignupForm() {
    // Show/hide card details based on plan
    elements.planSelect?.addEventListener('change', () => {
        const plan = elements.planSelect.value;
        if (plan === 'free') {
            elements.cardDetails.style.display = 'none';
        } else {
            elements.cardDetails.style.display = 'block';
        }
    });

    // Form submission
    elements.signupForm?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const submitBtn = elements.signupForm.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;

        // Show loading state
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating Account...';
        submitBtn.disabled = true;

        // Simulate API call
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Generate fake API key
        const apiKey = generateApiKey();
        elements.generatedApiKey.textContent = apiKey;

        // Show success state
        document.querySelector('.signup-form-wrapper').innerHTML = elements.signupSuccess.outerHTML;
        document.getElementById('signup-success').style.display = 'block';

        // Re-attach copy listener
        document.getElementById('copy-api-key')?.addEventListener('click', () => {
            copyToClipboard(apiKey);
            showCopyFeedback(document.getElementById('copy-api-key'));
        });
    });

    // Copy API key
    elements.copyApiKey?.addEventListener('click', () => {
        copyToClipboard(elements.generatedApiKey.textContent);
        showCopyFeedback(elements.copyApiKey);
    });

    // Format card number input
    document.getElementById('card-number')?.addEventListener('input', (e) => {
        let value = e.target.value.replace(/\s/g, '').replace(/\D/g, '');
        value = value.match(/.{1,4}/g)?.join(' ') || value;
        e.target.value = value;
    });

    // Format expiry input
    document.getElementById('card-expiry')?.addEventListener('input', (e) => {
        let value = e.target.value.replace(/\D/g, '');
        if (value.length >= 2) {
            value = value.slice(0, 2) + '/' + value.slice(2);
        }
        e.target.value = value;
    });
}

function generateApiKey() {
    const prefix = 'scam_';
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = prefix;
    for (let i = 0; i < 32; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
}

// ==========================================================================
// Mobile Menu
// ==========================================================================
function initMobileMenu() {
    elements.mobileMenuBtn?.addEventListener('click', () => {
        elements.navLinks?.classList.toggle('active');
    });
}

// ==========================================================================
// Smooth Scrolling
// ==========================================================================
function initSmoothScroll() {
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
    initCodeTabs();
    initCopyCode();
    initSignupForm();
    initMobileMenu();
    initSmoothScroll();

    console.log('🔧 Developers page initialized');
});
