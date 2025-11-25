/**
 * Scamlytic - Pricing Page JavaScript
 */

// ==========================================================================
// Pricing Data
// ==========================================================================
const pricingPlans = {
    pro: {
        name: 'Pro Plan',
        monthly: '$4.99',
        annual: '$3.99'
    },
    developer: {
        name: 'Developer Plan',
        monthly: '$29',
        annual: '$23'
    },
    business: {
        name: 'Business Plan',
        monthly: '$99',
        annual: '$79'
    }
};

// ==========================================================================
// DOM Elements
// ==========================================================================
const elements = {
    billingToggle: document.getElementById('billing-toggle'),
    toggleLabels: document.querySelectorAll('.toggle-label'),
    priceAmounts: document.querySelectorAll('.price-amount[data-monthly]'),

    // Checkout
    checkoutModal: document.getElementById('checkout-modal'),
    checkoutClose: document.getElementById('checkout-close'),
    checkoutForm: document.getElementById('checkout-form'),
    checkoutPlanInfo: document.getElementById('checkout-plan-info'),

    // FAQ
    faqItems: document.querySelectorAll('.faq-item'),

    // Mobile menu
    mobileMenuBtn: document.querySelector('.mobile-menu-btn'),
    navLinks: document.querySelector('.nav-links'),
};

// ==========================================================================
// State
// ==========================================================================
let isAnnualBilling = false;
let selectedPlan = null;

// ==========================================================================
// Billing Toggle
// ==========================================================================
function initBillingToggle() {
    elements.billingToggle?.addEventListener('click', () => {
        isAnnualBilling = !isAnnualBilling;

        // Update toggle state
        elements.billingToggle.classList.toggle('active', isAnnualBilling);

        // Update label states
        elements.toggleLabels.forEach(label => {
            const billing = label.dataset.billing;
            label.classList.toggle('active',
                (billing === 'annual' && isAnnualBilling) ||
                (billing === 'monthly' && !isAnnualBilling)
            );
        });

        // Update prices
        updatePrices();
    });

    // Set initial state
    elements.toggleLabels[0]?.classList.add('active');
}

function updatePrices() {
    elements.priceAmounts.forEach(el => {
        const monthly = el.dataset.monthly;
        const annual = el.dataset.annual;
        el.textContent = isAnnualBilling ? annual : monthly;
    });
}

// ==========================================================================
// Checkout Modal
// ==========================================================================
function openCheckout(plan) {
    selectedPlan = plan;
    const planData = pricingPlans[plan];

    if (planData && elements.checkoutPlanInfo) {
        const price = isAnnualBilling ? planData.annual : planData.monthly;
        const period = isAnnualBilling ? '/month (billed annually)' : '/month';

        elements.checkoutPlanInfo.innerHTML = `
            <span class="plan-tag">${planData.name}</span>
            <span class="plan-price">${price}${period}</span>
        `;
    }

    elements.checkoutModal?.classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeCheckout() {
    elements.checkoutModal?.classList.remove('active');
    document.body.style.overflow = '';
}

function initCheckout() {
    elements.checkoutClose?.addEventListener('click', closeCheckout);

    elements.checkoutModal?.querySelector('.modal-backdrop')?.addEventListener('click', closeCheckout);

    // Form submission
    elements.checkoutForm?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const submitBtn = elements.checkoutForm.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;

        // Show loading
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        submitBtn.disabled = true;

        // Simulate payment
        await new Promise(resolve => setTimeout(resolve, 2500));

        // Show success (in production, this would redirect to success page)
        alert('Payment successful! Welcome to Scamlytic ' + pricingPlans[selectedPlan]?.name + '!');

        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
        closeCheckout();
    });

    // Format card number
    document.getElementById('checkout-card')?.addEventListener('input', (e) => {
        let value = e.target.value.replace(/\s/g, '').replace(/\D/g, '');
        value = value.match(/.{1,4}/g)?.join(' ') || value;
        e.target.value = value;
    });

    // Format expiry
    document.getElementById('checkout-expiry')?.addEventListener('input', (e) => {
        let value = e.target.value.replace(/\D/g, '');
        if (value.length >= 2) {
            value = value.slice(0, 2) + '/' + value.slice(2);
        }
        e.target.value = value;
    });
}

// Make openCheckout available globally
window.openCheckout = openCheckout;

// ==========================================================================
// FAQ Accordion
// ==========================================================================
function initFAQ() {
    elements.faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');
        question?.addEventListener('click', () => {
            // Close other items
            elements.faqItems.forEach(other => {
                if (other !== item) {
                    other.classList.remove('active');
                }
            });

            // Toggle current item
            item.classList.toggle('active');
        });
    });
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
// Escape Key Handler
// ==========================================================================
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeCheckout();
    }
});

// ==========================================================================
// Initialize
// ==========================================================================
document.addEventListener('DOMContentLoaded', () => {
    initBillingToggle();
    initCheckout();
    initFAQ();
    initMobileMenu();
    initSmoothScroll();

    console.log('💰 Pricing page initialized');
});
