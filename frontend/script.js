// API configuration
const API_BASE_URL = 'http://localhost:8000';

// DOM Elements
const passwordInput = document.getElementById('password');
const togglePasswordBtn = document.getElementById('toggle-password');
const strengthMeter = document.querySelector('.meter-bar');
const strengthText = document.querySelector('.strength-text');

// Analysis elements
const lengthValue = document.getElementById('length-value');
const crackTime = document.getElementById('crack-time');
const uppercaseIndicator = document.getElementById('uppercase');
const lowercaseIndicator = document.getElementById('lowercase');
const numbersIndicator = document.getElementById('numbers');
const symbolsIndicator = document.getElementById('symbols');
const suggestionsList = document.getElementById('suggestions-list');

// Tabs
const tabButtons = document.querySelectorAll('.tab-button');
const tabContents = document.querySelectorAll('.tab-content');

// Brute force elements
const algorithmSelect = document.getElementById('algorithm');
const runBruteForceBtn = document.getElementById('run-brute-force');
const bruteForceResults = document.querySelector('.brute-force-results');
const bruteForceLoader = document.querySelector('.loader');
const bruteStatus = document.getElementById('brute-status');
const bruteTime = document.getElementById('brute-time');
const bruteAttempts = document.getElementById('brute-attempts');
const bruteCracked = document.getElementById('brute-cracked');

// API Check elements
const apiCheckBtn = document.getElementById('api-check-btn');
const apiResultBox = document.getElementById('apiResultBox');
const apiStrength = document.getElementById('api-strength');
const apiFeedbackList = document.getElementById('api-feedback-list');
const apiSuggestionBox = document.getElementById('api-suggestion-box');
const apiSuggestion = document.getElementById('api-suggestion');
const apiCopyBtn = document.getElementById('api-copy-btn');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Add event listeners
    passwordInput.addEventListener('input', throttle(checkPasswordStrength, 300));
    togglePasswordBtn.addEventListener('click', togglePasswordVisibility);
    
    // Tab switching
    tabButtons.forEach(button => {
        button.addEventListener('click', () => switchTab(button.dataset.tab));
    });
    
    // Brute force test
    runBruteForceBtn.addEventListener('click', runBruteForceTest);
    
    // API Check
    apiCheckBtn.addEventListener('click', checkPasswordWithAPI);
    apiCopyBtn.addEventListener('click', copyApiSuggestion);
    
    // Disable the brute force button if no password
    checkBruteForceButtonState();
    passwordInput.addEventListener('input', checkBruteForceButtonState);
});

/**
 * Throttle function to limit how often a function runs
 */
function throttle(func, delay) {
    let lastCall = 0;
    return function(...args) {
        const now = new Date().getTime();
        if (now - lastCall >= delay) {
            lastCall = now;
            func.apply(this, args);
        }
    };
}

/**
 * Toggle password visibility
 */
function togglePasswordVisibility() {
    const icon = togglePasswordBtn.querySelector('i');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        passwordInput.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

/**
 * Switch between tabs
 */
function switchTab(tabId) {
    // Update active tab button
    tabButtons.forEach(button => {
        if (button.dataset.tab === tabId) {
            button.classList.add('active');
        } else {
            button.classList.remove('active');
        }
    });
    
    // Show active tab content
    tabContents.forEach(content => {
        if (content.id === `${tabId}-tab`) {
            content.classList.remove('hidden');
        } else {
            content.classList.add('hidden');
        }
    });
}

/**
 * Update boolean indicators (checkmarks/X marks)
 */
function updateIndicator(element, value) {
    // Clear existing content
    element.innerHTML = '';
    
    // Add appropriate icon
    const icon = document.createElement('i');
    if (value) {
        icon.className = 'fas fa-check success';
    } else {
        icon.className = 'fas fa-times fail';
    }
    
    element.appendChild(icon);
}

/**
 * Check if brute force button should be enabled
 */
function checkBruteForceButtonState() {
    const password = passwordInput.value.trim();
    
    if (password.length > 0 && password.length <= 6) {
        runBruteForceBtn.disabled = false;
    } else {
        runBruteForceBtn.disabled = true;
    }
}

/**
 * Check password strength via API
 */
async function checkPasswordStrength() {
    const password = passwordInput.value.trim();
    
    // Reset if empty
    if (!password) {
        resetStrengthIndicators();
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/check-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ password }),
        });
        
        if (!response.ok) {
            throw new Error('API request failed');
        }
        
        const data = await response.json();
        updateStrengthIndicators(data);
    } catch (error) {
        console.error('Error checking password strength:', error);
        // Fallback to basic checks if API fails
        performBasicStrengthCheck(password);
    }
}

/**
 * Update strength indicators based on API response
 */
function updateStrengthIndicators(data) {
    // Update meter and text
    strengthMeter.className = 'meter-bar';
    
    const strengthClasses = ['very-weak', 'weak', 'medium', 'strong', 'very-strong'];
    const strengthClass = strengthClasses[data.score];
    strengthMeter.classList.add(strengthClass);
    
    strengthText.textContent = data.strength_text;
    
    // Update analysis values
    lengthValue.textContent = data.length;
    crackTime.textContent = data.crack_time_display;
    
    // Update boolean indicators
    updateIndicator(uppercaseIndicator, data.has_upper);
    updateIndicator(lowercaseIndicator, data.has_lower);
    updateIndicator(numbersIndicator, data.has_digit);
    updateIndicator(symbolsIndicator, data.has_symbol);
    
    // Update suggestions
    suggestionsList.innerHTML = '';
    if (data.suggestions.length > 0) {
        data.suggestions.forEach(suggestion => {
            const li = document.createElement('li');
            li.textContent = suggestion;
            suggestionsList.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.textContent = 'Your password looks good!';
        suggestionsList.appendChild(li);
    }
}

/**
 * Reset strength indicators to default state
 */
function resetStrengthIndicators() {
    strengthMeter.className = 'meter-bar';
    strengthText.textContent = 'Enter a password';
    
    lengthValue.textContent = '0';
    crackTime.textContent = '-';
    
    // Reset boolean indicators
    uppercaseIndicator.innerHTML = '<i class="fas fa-minus"></i>';
    lowercaseIndicator.innerHTML = '<i class="fas fa-minus"></i>';
    numbersIndicator.innerHTML = '<i class="fas fa-minus"></i>';
    symbolsIndicator.innerHTML = '<i class="fas fa-minus"></i>';
    
    // Reset suggestions
    suggestionsList.innerHTML = '<li>Enter a password to get suggestions</li>';
}

/**
 * Basic strength check as fallback if API fails
 */
function performBasicStrengthCheck(password) {
    const length = password.length;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSymbol = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    // Calculate simple score (0-4)
    let score = 0;
    if (length >= 8) score += 1;
    if (hasUpper && hasLower) score += 1;
    if (hasDigit) score += 1;
    if (hasSymbol) score += 1;
    if (length >= 12) score += 1;
    
    score = Math.min(score, 4);
    
    // Create a data object similar to API response
    const data = {
        length,
        has_upper: hasUpper,
        has_lower: hasLower,
        has_digit: hasDigit,
        has_symbol: hasSymbol,
        score,
        strength_text: ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong'][score],
        crack_time_display: calculateCrackTime(password, score),
        suggestions: generateSuggestions(password, hasUpper, hasLower, hasDigit, hasSymbol)
    };
    
    updateStrengthIndicators(data);
}

/**
 * Calculate crack time for basic strength check
 */
function calculateCrackTime(password, score) {
    const times = [
        "less than a second",
        "minutes",
        "hours to days",
        "months",
        "centuries"
    ];
    
    return times[score];
}

/**
 * Generate suggestions for basic strength check
 */
function generateSuggestions(password, hasUpper, hasLower, hasDigit, hasSymbol) {
    const suggestions = [];
    
    if (password.length < 8) {
        suggestions.push("Use at least 8 characters");
    }
    
    if (!hasUpper) {
        suggestions.push("Add uppercase letters");
    }
    
    if (!hasLower) {
        suggestions.push("Add lowercase letters");
    }
    
    if (!hasDigit) {
        suggestions.push("Add numbers");
    }
    
    if (!hasSymbol) {
        suggestions.push("Add symbols (!@#$%^&*)");
    }
    
    if (password.length < 12) {
        suggestions.push("Consider using a longer password (12+ characters)");
    }
    
    return suggestions;
}

/**
 * Run brute force test
 */
async function runBruteForceTest() {
    const password = passwordInput.value.trim();
    const algorithm = algorithmSelect.value;
    
    if (!password) {
        return;
    }
    
    // Show loader, hide results
    bruteForceLoader.classList.remove('hidden');
    bruteForceResults.classList.add('hidden');
    runBruteForceBtn.disabled = true;
    
    try {
        const response = await fetch(`${API_BASE_URL}/brute-force`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                password,
                algorithm,
                max_attempts: 1000000 // Limit for performance
            }),
        });
        
        if (!response.ok) {
            throw new Error('API request failed');
        }
        
        const data = await response.json();
        updateBruteForceResults(data);
    } catch (error) {
        console.error('Error running brute force test:', error);
        showBruteForceError();
    } finally {
        bruteForceLoader.classList.add('hidden');
        bruteForceResults.classList.remove('hidden');
        runBruteForceBtn.disabled = false;
    }
}

/**
 * Update brute force results UI
 */
function updateBruteForceResults(data) {
    bruteStatus.textContent = data.success ? 'Password Cracked! ⚠️' : 'Password Not Cracked ✅';
    bruteStatus.className = data.success ? 'result-value fail' : 'result-value success';
    
    bruteTime.textContent = `${data.time_taken.toFixed(3)} seconds`;
    bruteAttempts.textContent = data.attempts.toLocaleString();
    bruteCracked.textContent = data.success ? data.cracked_password : 'N/A';
}

/**
 * Show error message for brute force test
 */
function showBruteForceError() {
    bruteStatus.textContent = 'Test Failed';
    bruteStatus.className = 'result-value fail';
    bruteTime.textContent = 'N/A';
    bruteAttempts.textContent = 'N/A';
    bruteCracked.textContent = 'N/A';
}

/**
 * Check password with the external API
 */
async function checkPasswordWithAPI() {
    const password = passwordInput.value.trim();
    
    if (!password) {
        alert('Please enter a password first');
        return;
    }
    
    apiCheckBtn.disabled = true;
    apiCheckBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking...';
    
    try {
        const res = await fetch(`${API_BASE_URL}/check-strength`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password })
        });

        const data = await res.json();
        
        // Clear previous strength classes
        apiStrength.classList.remove("strength-weak", "strength-medium", "strength-strong");
        apiStrength.textContent = data.strength;
        
        // Add appropriate class based on strength
        if (data.strength.toLowerCase() === "weak") {
            apiStrength.classList.add("strength-weak");
        } else if (data.strength.toLowerCase() === "medium") {
            apiStrength.classList.add("strength-medium");
        } else if (data.strength.toLowerCase() === "strong") {
            apiStrength.classList.add("strength-strong");
        }

        apiFeedbackList.innerHTML = "";
        if (data.feedback && data.feedback.length) {
            data.feedback.forEach(msg => {
                const li = document.createElement("li");
                li.textContent = msg;
                apiFeedbackList.appendChild(li);
            });
        }

        apiResultBox.classList.remove("hidden");

        if (data.suggestion) {
            apiSuggestion.textContent = data.suggestion;
            apiSuggestionBox.classList.remove("hidden");
        } else {
            apiSuggestionBox.classList.add("hidden");
        }
    } catch (error) {
        console.error("Error checking password strength:", error);
        alert("Failed to check password strength with API");
    } finally {
        apiCheckBtn.disabled = false;
        apiCheckBtn.innerHTML = '<i class="fas fa-server"></i> Check with API';
    }
}

/**
 * Copy API suggestion to clipboard
 */
function copyApiSuggestion() {
    const suggestion = apiSuggestion.textContent;
    if (!suggestion) return;
    
    navigator.clipboard.writeText(suggestion)
        .then(() => {
            const originalText = apiCopyBtn.textContent;
            apiCopyBtn.textContent = '✓ Copied!';
            setTimeout(() => {
                apiCopyBtn.textContent = originalText;
            }, 2000);
        })
        .catch(err => {
            console.error('Failed to copy text: ', err);
            alert('Failed to copy password to clipboard');
        });
}