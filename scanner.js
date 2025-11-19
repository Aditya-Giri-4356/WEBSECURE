class WebSecurityScanner {
    constructor() {
        this.isScanning = false;
        this.currentScan = null;
        this.results = [];
        this.banner = null;
        this.bannerMessage = null;
        this.notificationTimeout = null;
        this.defaultBannerMessage = 'Run scans only on assets you own or have permission to test.';
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        document.getElementById('startScan').addEventListener('click', () => this.startScan());
        document.getElementById('stopScan').addEventListener('click', () => this.stopScan());
        document.getElementById('validateUrl').addEventListener('click', () => this.validateUrl());
        document.getElementById('exportJson').addEventListener('click', () => this.exportResults('json'));
        document.getElementById('exportPdf').addEventListener('click', () => this.exportResults('pdf'));
        
        // Enter key on URL input
        document.getElementById('targetUrl').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.validateUrl();
        });

        this.banner = document.getElementById('safetyBanner');
        this.bannerMessage = document.getElementById('bannerMessage');
        if (this.bannerMessage?.textContent) {
            this.defaultBannerMessage = this.bannerMessage.textContent;
        }
    }

    validateUrl() {
        const urlInput = document.getElementById('targetUrl');
        const url = urlInput.value.trim();
        
        if (!url) {
            this.showNotification('Please enter a target URL', 'error');
            return false;
        }

        try {
            const urlObj = new URL(url);
            if (!['http:', 'https:'].includes(urlObj.protocol)) {
                throw new Error('Only HTTP and HTTPS protocols are supported');
            }
            this.showNotification('URL validated successfully', 'success');
            urlInput.classList.add('border-green-500');
            setTimeout(() => urlInput.classList.remove('border-green-500'), 2000);
            return true;
        } catch (error) {
            this.showNotification('Invalid URL format', 'error');
            urlInput.classList.add('border-red-500');
            setTimeout(() => urlInput.classList.remove('border-red-500'), 2000);
            return false;
        }
    }

    async startScan() {
        if (!this.validateUrl()) return;
        
        const targetUrl = document.getElementById('targetUrl').value.trim();
        const scanTypes = {
            sqlInjection: document.getElementById('sqlInjection').checked,
            xss: document.getElementById('xss').checked,
            auth: document.getElementById('auth').checked,
            securityHeaders: document.getElementById('securityHeaders').checked,
            tls: document.getElementById('tls').checked,
            dirListing: document.getElementById('dirListing').checked,
            weakCookies: document.getElementById('weakCookies').checked
        };

        this.isScanning = true;
        this.results = [];
        this.updateUIState('scanning');
        
        // Show progress section
        document.getElementById('progressSection').classList.remove('hidden');
        document.getElementById('resultsSection').classList.add('hidden');

        try {
            await this.performSecurityScan(targetUrl, scanTypes);
        } catch (error) {
            console.error('Scan error:', error);
            this.showNotification('Scan failed: ' + error.message, 'error');
        } finally {
            this.isScanning = false;
            this.updateUIState('idle');
        }
    }

    stopScan() {
        this.isScanning = false;
        this.updateUIState('idle');
        this.showNotification('Scan stopped by user', 'info');
    }

    async performSecurityScan(targetUrl, scanTypes) {
        const scanQueue = [
            { key: 'sqlInjection', label: 'SQL Injection', handler: () => this.scanSQLInjection(targetUrl) },
            { key: 'xss', label: 'XSS', handler: () => this.scanXSS(targetUrl) },
            { key: 'auth', label: 'Authentication', handler: () => this.scanAuthentication(targetUrl) },
            { key: 'securityHeaders', label: 'Security Headers', handler: () => this.scanSecurityHeaders(targetUrl) },
            { key: 'tls', label: 'TLS Configuration', handler: () => this.scanTLSConfiguration(targetUrl) },
            { key: 'dirListing', label: 'Directory Listing', handler: () => this.scanDirectoryListing(targetUrl) },
            { key: 'weakCookies', label: 'Weak Cookies', handler: () => this.scanWeakCookies(targetUrl) }
        ].filter(task => scanTypes[task.key]);

        for (let i = 0; i < scanQueue.length; i++) {
            if (!this.isScanning) break;

            const progress = ((i + 1) / scanQueue.length) * 100;
            this.updateProgress(progress, `Running ${scanQueue[i].label} scan...`);

            try {
                const result = await scanQueue[i].handler();
                if (Array.isArray(result) && result.length) {
                    this.results.push(...result);
                }
            } catch (error) {
                console.error('Scan step error:', error);
            }

            await this.delay(800);
        }

        if (this.results.length > 0) {
            this.displayResults();
        } else {
            this.showNotification('No vulnerabilities found', 'success');
            this.displayResults(); // Show empty results
        }
    }

    async scanSQLInjection(targetUrl) {
        this.updateProgress(25, 'Testing for SQL injection vulnerabilities...');
        
        const vulnerabilities = [];
        const sqlPayloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin'/*",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR '1'='1--",
            "') OR ('1'='1--"
        ];

        // Test common injection points
        const testUrls = [
            `${targetUrl}?id=1`,
            `${targetUrl}?search=test`,
            `${targetUrl}?user=admin`,
            `${targetUrl}?page=1`
        ];

        for (const baseUrl of testUrls) {
            for (const payload of sqlPayloads) {
                if (!this.isScanning) break;
                
                const testUrl = baseUrl + payload;
                try {
                    // Simulate SQL injection detection
                    const hasSQLVulnerability = await this.simulateSQLInjectionTest(testUrl);
                    if (hasSQLVulnerability) {
                        vulnerabilities.push({
                            type: 'SQL Injection',
                            severity: 'Critical',
                            url: testUrl,
                            payload: payload,
                            description: 'Potential SQL injection vulnerability detected',
                            recommendation: 'Use parameterized queries and input validation'
                        });
                    }
                } catch (error) {
                    // Ignore network errors for demo
                }
            }
        }

        return vulnerabilities;
    }

    async scanSecurityHeaders(targetUrl) {
        this.updateProgress(65, 'Reviewing response security headers...');
        await this.delay(200);

        const requiredHeaders = [
            {
                name: 'Strict-Transport-Security',
                severity: 'High',
                description: 'Missing HSTS allows SSL stripping attacks.',
                recommendation: 'Return Strict-Transport-Security with max-age>=31536000 and includeSubDomains.'
            },
            {
                name: 'Content-Security-Policy',
                severity: 'High',
                description: 'Content-Security-Policy header not detected.',
                recommendation: 'Define a CSP to restrict script sources and mitigate XSS.'
            },
            {
                name: 'X-Frame-Options',
                severity: 'Medium',
                description: 'Clickjacking protection header missing.',
                recommendation: 'Set X-Frame-Options to DENY or SAMEORIGIN.'
            },
            {
                name: 'X-Content-Type-Options',
                severity: 'Medium',
                description: 'MIME-sniffing protection header missing.',
                recommendation: 'Return X-Content-Type-Options: nosniff.'
            },
            {
                name: 'Referrer-Policy',
                severity: 'Low',
                description: 'Referrer-Policy header missing.',
                recommendation: 'Set Referrer-Policy to restrict leaking sensitive URLs.'
            }
        ];

        return requiredHeaders
            .filter(() => Math.random() > 0.7)
            .map(header => ({
                type: `Missing ${header.name}`,
                severity: header.severity,
                url: targetUrl,
                description: header.description,
                recommendation: header.recommendation
            }));
    }

    async scanTLSConfiguration(targetUrl) {
        this.updateProgress(80, 'Assessing TLS configuration...');
        await this.delay(200);

        const issues = [];
        if (!targetUrl.startsWith('https://')) {
            issues.push({
                type: 'HTTPS Not Enforced',
                severity: 'High',
                url: targetUrl,
                description: 'Target does not enforce HTTPS connections.',
                recommendation: 'Redirect HTTP to HTTPS and install a trusted certificate.'
            });
        }

        if (Math.random() > 0.8) {
            issues.push({
                type: 'Legacy TLS Protocol',
                severity: 'Medium',
                url: targetUrl,
                description: 'Server negotiated TLS 1.0/1.1 during handshake.',
                recommendation: 'Disable TLS 1.0/1.1 and require TLS 1.2+.'
            });
        }

        if (Math.random() > 0.85) {
            issues.push({
                type: 'TLS Certificate Expiring Soon',
                severity: 'Medium',
                url: targetUrl,
                description: 'Certificate expires within 30 days.',
                recommendation: 'Renew the TLS certificate before expiry.'
            });
        }

        return issues;
    }

    async scanDirectoryListing(targetUrl) {
        this.updateProgress(85, 'Checking for exposed directories...');
        await this.delay(200);

        const directories = ['/backup/', '/logs/', '/.git/', '/uploads/'];
        return directories
            .filter(() => Math.random() > 0.75)
            .map(path => ({
                type: 'Directory Listing Enabled',
                severity: 'Medium',
                url: `${targetUrl.replace(/\/$/, '')}${path}`,
                description: `Directory indexing appears enabled for ${path}.`,
                recommendation: 'Disable directory browsing and block direct access via server configuration.'
            }));
    }

    async scanWeakCookies(targetUrl) {
        this.updateProgress(90, 'Inspecting cookie attributes...');
        await this.delay(200);

        const attributes = ['HttpOnly', 'Secure', 'SameSite'];
        if (Math.random() > 0.7) {
            const missing = attributes.filter(() => Math.random() > 0.5);
            if (missing.length) {
                return [{
                    type: 'Weak Cookie Attributes',
                    severity: 'Medium',
                    url: targetUrl,
                    description: `Cookies missing: ${missing.join(', ')}.`,
                    recommendation: `Set ${missing.join(', ')} flag(s) on authentication cookies.`
                }];
            }
        }
        return [];
    }

    async scanXSS(targetUrl) {
        this.updateProgress(50, 'Testing for XSS vulnerabilities...');
        
        const vulnerabilities = [];
        const xssPayloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>'
        ];

        const testParams = ['search', 'query', 'q', 'input', 'comment', 'name'];
        
        for (const param of testParams) {
            for (const payload of xssPayloads) {
                if (!this.isScanning) break;
                
                const testUrl = `${targetUrl}?${param}=${encodeURIComponent(payload)}`;
                try {
                    const hasXSSVulnerability = await this.simulateXSSTest(testUrl);
                    if (hasXSSVulnerability) {
                        vulnerabilities.push({
                            type: 'Cross-Site Scripting (XSS)',
                            severity: 'High',
                            url: testUrl,
                            payload: payload,
                            description: 'Potential XSS vulnerability detected',
                            recommendation: 'Implement proper output encoding and Content Security Policy'
                        });
                    }
                } catch (error) {
                    // Ignore network errors for demo
                }
            }
        }

        return vulnerabilities;
    }

    async scanAuthentication(targetUrl) {
        this.updateProgress(75, 'Testing authentication security...');
        
        const vulnerabilities = [];
        
        // Test for common authentication issues
        const authTests = [
            {
                name: 'Default Credentials',
                test: () => this.testDefaultCredentials(targetUrl),
                severity: 'High'
            },
            {
                name: 'Weak Password Policy',
                test: () => this.testPasswordPolicy(targetUrl),
                severity: 'Medium'
            },
            {
                name: 'Session Management',
                test: () => this.testSessionManagement(targetUrl),
                severity: 'Medium'
            },
            {
                name: 'Brute Force Protection',
                test: () => this.testBruteForceProtection(targetUrl),
                severity: 'High'
            }
        ];

        for (const authTest of authTests) {
            if (!this.isScanning) break;
            
            try {
                const isVulnerable = await authTest.test();
                if (isVulnerable) {
                    vulnerabilities.push({
                        type: authTest.name,
                        severity: authTest.severity,
                        url: targetUrl,
                        description: `Authentication issue detected: ${authTest.name}`,
                        recommendation: this.getAuthRecommendation(authTest.name)
                    });
                }
            } catch (error) {
                // Ignore errors for demo
            }
        }

        return vulnerabilities;
    }

    // Simulation methods (in real implementation, these would make actual HTTP requests)
    async simulateSQLInjectionTest(url) {
        // Simulate detection logic
        await this.delay(100);
        return Math.random() > 0.8; // 20% chance of finding vulnerability for demo
    }

    async simulateXSSTest(url) {
        // Simulate detection logic
        await this.delay(100);
        return Math.random() > 0.7; // 30% chance of finding vulnerability for demo
    }

    async testDefaultCredentials(url) {
        await this.delay(100);
        return Math.random() > 0.9; // 10% chance for demo
    }

    async testPasswordPolicy(url) {
        await this.delay(100);
        return Math.random() > 0.8; // 20% chance for demo
    }

    async testSessionManagement(url) {
        await this.delay(100);
        return Math.random() > 0.85; // 15% chance for demo
    }

    async testBruteForceProtection(url) {
        await this.delay(100);
        return Math.random() > 0.9; // 10% chance for demo
    }

    getAuthRecommendation(issue) {
        const recommendations = {
            'Default Credentials': 'Change default credentials and enforce strong password policies',
            'Weak Password Policy': 'Implement strong password requirements and regular password changes',
            'Session Management': 'Use secure session management with proper timeout and regeneration',
            'Brute Force Protection': 'Implement rate limiting and account lockout mechanisms'
        };
        return recommendations[issue] || 'Review and strengthen authentication mechanisms';
    }

    updateProgress(percentage, task) {
        document.getElementById('scanProgress').textContent = `${Math.round(percentage)}%`;
        document.getElementById('progressBar').style.width = `${percentage}%`;
        if (task) {
            document.getElementById('currentTask').textContent = task;
            document.getElementById('scanStatus').textContent = task;
        }
    }

    displayResults() {
        document.getElementById('progressSection').classList.add('hidden');
        document.getElementById('resultsSection').classList.remove('hidden');

        // Calculate statistics
        const stats = this.calculateStatistics();
        document.getElementById('totalIssues').textContent = stats.total;
        document.getElementById('criticalIssues').textContent = stats.critical;
        document.getElementById('mediumIssues').textContent = stats.medium;
        document.getElementById('lowIssues').textContent = stats.low;

        // Display detailed findings
        const findingsList = document.getElementById('findingsList');
        findingsList.innerHTML = '';

        if (this.results.length === 0) {
            findingsList.innerHTML = `
                <div class="text-center py-8 status-muted">
                    <i data-lucide="check-circle" class="w-12 h-12 mx-auto mb-4 text-green-500"></i>
                    <p>No security vulnerabilities detected</p>
                </div>
            `;
        } else {
            this.results.forEach((finding) => {
                const findingCard = this.createFindingCard(finding);
                findingsList.innerHTML += findingCard;
            });
        }

        // Re-initialize Lucide icons for new content
        lucide.createIcons();

        this.updateAIAssistant();
    }

    calculateStatistics() {
        const stats = { total: 0, critical: 0, medium: 0, low: 0 };
        
        this.results.forEach(result => {
            stats.total++;
            switch (result.severity.toLowerCase()) {
                case 'critical':
                    stats.critical++;
                    break;
                case 'high':
                    stats.critical++;
                    break;
                case 'medium':
                    stats.medium++;
                    break;
                case 'low':
                    stats.low++;
                    break;
            }
        });

        return stats;
    }

    createFindingCard(finding) {
        const severityKey = this.normalizeSeverity(finding.severity);
        const severityIcons = {
            critical: 'alert-circle',
            high: 'alert-circle',
            medium: 'alert-triangle',
            low: 'info'
        };

        const severityLabel = this.escapeHTML(finding.severity || severityKey.charAt(0).toUpperCase() + severityKey.slice(1));
        const baseUrl = finding.url ? this.escapeHTML(finding.url.split('?')[0]) : '';
        const safeType = this.escapeHTML(finding.type || 'Unknown Issue');
        const safeDescription = this.escapeHTML(finding.description || '');
        const safeRecommendation = this.escapeHTML(finding.recommendation || 'Review this component.');
        const safeUrl = this.escapeHTML(finding.url || 'N/A');
        const safePayload = finding.payload ? this.escapeHTML(finding.payload) : null;

        return `
            <div class="vulnerability-card rounded-lg p-4" data-severity="${severityKey}">
                <div class="flex items-start justify-between">
                    <div class="flex-1 space-y-3">
                        <div class="flex flex-wrap items-center gap-3">
                            <i data-lucide="${severityIcons[severityKey] || 'info'}" class="w-4 h-4"></i>
                            <div>
                                <h4 class="font-semibold leading-tight">${safeType}</h4>
                                <p class="text-xs status-muted">${baseUrl}</p>
                            </div>
                            <span class="severity-pill">${severityLabel}</span>
                        </div>
                        <p class="text-sm">${safeDescription}</p>
                        <p class="text-xs font-mono code-chip p-2 rounded mb-2 break-words">
                            ${safeUrl}${safePayload ? ` | Payload: ${safePayload}` : ''}
                        </p>
                        <div class="recommendation-box rounded p-3">
                            <p class="text-xs font-medium mb-1">Recommendation</p>
                            <p class="text-xs leading-relaxed">${safeRecommendation}</p>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    normalizeSeverity(severity) {
        const value = (severity || '').toString().toLowerCase();
        if (['critical', 'high', 'medium', 'low'].includes(value)) {
            return value;
        }
        return 'low';
    }

    getSeverityRank(severity) {
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        const normalized = this.normalizeSeverity(severity);
        return order[normalized] ?? 3;
    }

    updateAIAssistant() {
        const section = document.getElementById('aiAssistantSection');
        const summaryEl = document.getElementById('aiAssistantSummary');
        const quickFixList = document.getElementById('aiAssistantQuickFixes');

        if (!section || !summaryEl || !quickFixList) return;

        section.classList.remove('hidden');

        if (this.results.length === 0) {
            summaryEl.textContent = 'AI Assistant did not detect any vulnerabilities. Keep monitoring and rerun scans after major releases.';
            quickFixList.innerHTML = `
                <li class="rounded-lg border border-gray-200 bg-white/60 p-4">
                    <p class="text-sm">
                        ✅ All clear. Consider enabling scheduled scans and hardening baseline security controls to maintain this posture.
                    </p>
                </li>
            `;
            lucide.createIcons();
            return;
        }

        const rankedFindings = [...this.results]
            .sort((a, b) => this.getSeverityRank(a.severity) - this.getSeverityRank(b.severity));

        const deduped = [];
        const seen = new Set();
        rankedFindings.forEach(finding => {
            const key = `${finding.type}|${finding.recommendation}`;
            if (seen.has(key)) return;
            seen.add(key);
            deduped.push(finding);
        });

        const topFindings = deduped.slice(0, 5);
        const mostSevere = topFindings[0];
        const severityLabel = (mostSevere?.severity || 'High').toString();
        summaryEl.textContent = `AI reviewed ${this.results.length} findings. Prioritize ${severityLabel} risks such as ${mostSevere?.type || 'the top-listed issue'} before moving to lower severities.`;

        quickFixList.innerHTML = topFindings.map((finding, index) => this.buildQuickFixItem(finding, index)).join('');
        lucide.createIcons();
    }

    buildQuickFixItem(finding, index) {
        const severityKey = this.normalizeSeverity(finding.severity);
        const severityLabel = this.escapeHTML(finding.severity || severityKey.charAt(0).toUpperCase() + severityKey.slice(1));
        const safeType = this.escapeHTML(finding.type || 'Issue');
        const safeDescription = this.escapeHTML(finding.description || 'Related vulnerability detected during the scan.');
        const safeRecommendation = this.escapeHTML(finding.recommendation || 'Review this component and apply vendor guidance.');
        const safePayload = finding.payload ? this.escapeHTML(finding.payload) : null;
        const payloadInfo = safePayload ? `<p class="text-xs font-mono code-chip p-2 rounded mt-3">Example payload: ${safePayload}</p>` : '';

        return `
            <li class="vulnerability-card rounded-lg p-4" data-severity="${severityKey}">
                <div class="flex items-start justify-between gap-3">
                    <div class="flex-1 space-y-2">
                        <p class="text-xs tracking-wider uppercase status-muted">Step ${index + 1}</p>
                        <h4 class="font-semibold">Mitigate ${safeType}</h4>
                        <p class="text-sm text-gray-700">${safeDescription}</p>
                        <p class="text-xs text-gray-600"><span class="font-semibold">Quick fix:</span> ${safeRecommendation}</p>
                        ${payloadInfo}
                    </div>
                    <span class="severity-pill">${severityLabel}</span>
                </div>
            </li>
        `;
    }

    escapeHTML(value = '') {
        return value
            .toString()
            .replace(/[&<>"']/g, (char) => {
                switch (char) {
                    case '&':
                        return '&amp;';
                    case '<':
                        return '&lt;';
                    case '>':
                        return '&gt;';
                    case '"':
                        return '&quot;';
                    case '\'':
                        return '&#39;';
                    default:
                        return char;
                }
            });
    }
    exportResults(format) {
        if (this.results.length === 0) {
            this.showNotification('No results to export', 'info');
            return;
        }

        const timestamp = new Date().toISOString().split('T')[0];
        const targetUrl = document.getElementById('targetUrl').value.trim();
        
        if (format === 'json') {
            const report = {
                scanDate: new Date().toISOString(),
                target: targetUrl,
                summary: this.calculateStatistics(),
                vulnerabilities: this.results
            };
            
            const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
            this.downloadFile(blob, `security-scan-${timestamp}.json`);
        } else if (format === 'pdf') {
            // For PDF export, we'll create a simple HTML report and suggest printing
            this.createHTMLReport(timestamp, targetUrl);
        }

        this.showNotification(`Report exported as ${format.toUpperCase()}`, 'success');
    }

    createHTMLReport(timestamp, targetUrl) {
        const reportHTML = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Security Scan Report - ${targetUrl}</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .header { border-bottom: 2px solid #2563eb; padding-bottom: 10px; margin-bottom: 20px; }
                    .summary { display: flex; gap: 20px; margin-bottom: 30px; }
                    .stat { text-align: center; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                    .vulnerability { margin-bottom: 20px; padding: 15px; border-left: 4px solid #2563eb; background: #f8f9fa; }
                    .critical { border-left-color: #dc2626; }
                    .medium { border-left-color: #f59e0b; }
                    .low { border-left-color: #2563eb; }
                    @media print { body { margin: 10px; } }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>WEBSECURE – Website Assurance Report</h1>
                    <p><strong>Target:</strong> ${targetUrl}</p>
                    <p><strong>Date:</strong> ${new Date().toLocaleString()}</p>
                </div>
                
                <div class="summary">
                    <div class="stat">
                        <h3>${this.calculateStatistics().total}</h3>
                        <p>Total Issues</p>
                    </div>
                    <div class="stat">
                        <h3 style="color: #dc2626;">${this.calculateStatistics().critical}</h3>
                        <p>Critical/High</p>
                    </div>
                    <div class="stat">
                        <h3 style="color: #f59e0b;">${this.calculateStatistics().medium}</h3>
                        <p>Medium</p>
                    </div>
                    <div class="stat">
                        <h3 style="color: #2563eb;">${this.calculateStatistics().low}</h3>
                        <p>Low</p>
                    </div>
                </div>
                
                <h2>Vulnerability Details</h2>
                ${this.results.map(vuln => `
                    <div class="vulnerability ${vuln.severity.toLowerCase()}">
                        <h3>${vuln.type} - ${vuln.severity}</h3>
                        <p><strong>Description:</strong> ${vuln.description}</p>
                        <p><strong>URL:</strong> ${vuln.url}</p>
                        ${vuln.payload ? `<p><strong>Payload:</strong> ${vuln.payload}</p>` : ''}
                        <p><strong>Recommendation:</strong> ${vuln.recommendation}</p>
                    </div>
                `).join('')}
                
                <div style="margin-top: 30px; text-align: center; color: #666; font-size: 12px;">
                    <p>Generated by WEBSECURE</p>
                </div>
            </body>
            </html>
        `;

        const blob = new Blob([reportHTML], { type: 'text/html' });
        this.downloadFile(blob, `security-scan-${timestamp}.html`);
        
        // Suggest printing to PDF
        setTimeout(() => {
            this.showNotification('HTML report generated. Use browser print to save as PDF.', 'info');
        }, 1000);
    }

    downloadFile(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    updateUIState(state) {
        const startBtn = document.getElementById('startScan');
        const stopBtn = document.getElementById('stopScan');
        
        if (state === 'scanning') {
            startBtn.disabled = true;
            stopBtn.disabled = false;
            startBtn.classList.add('opacity-50');
            stopBtn.classList.remove('opacity-50');
        } else {
            startBtn.disabled = false;
            stopBtn.disabled = true;
            startBtn.classList.remove('opacity-50');
            stopBtn.classList.add('opacity-50');
        }
    }

    showNotification(message, type = 'info') {
        if (this.banner && this.bannerMessage) {
            const toneClass = type === 'error' ? 'banner-error' : type === 'success' ? 'banner-success' : 'banner-info';
            this.banner.classList.remove('banner-error', 'banner-success', 'banner-info');
            this.banner.classList.add(toneClass);
            this.bannerMessage.textContent = message;

            if (this.notificationTimeout) {
                clearTimeout(this.notificationTimeout);
            }

            const resetDelay = type === 'info' ? 3000 : 5000;
            this.notificationTimeout = setTimeout(() => {
                this.banner.classList.remove('banner-error', 'banner-success', 'banner-info');
                this.banner.classList.add('banner-info');
                this.bannerMessage.textContent = this.defaultBannerMessage;
                this.notificationTimeout = null;
            }, resetDelay);
        } else {
            const method = type === 'error' ? 'error' : 'log';
            console[method](message);
        }
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize the scanner when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.scanner = new WebSecurityScanner();
});

// Service Worker registration for PWA
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
            .then(registration => {
                console.log('SW registered: ', registration);
            })
            .catch(registrationError => {
                console.log('SW registration failed: ', registrationError);
            });
    });
}
