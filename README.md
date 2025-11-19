# WEBSECURE 🔒

WEBSECURE is a professional web application scanner that helps you check if your website is truly secure across SQL injection, XSS, authentication, misconfiguration, and policy gaps. Use it in the browser or install it as a Progressive Web App (PWA) for standalone workflows.

## Features

### 🛡️ Vulnerability Detection
- **SQL Injection Scanning**: Tests for common SQL injection patterns and payloads
- **XSS Detection**: Identifies cross-site scripting vulnerabilities
- **Authentication Security**: Detects weak authentication mechanisms
- **Security Header Audit**: Flags missing HSTS, CSP, XFO, XCTO, Referrer-Policy
- **TLS Configuration Review**: Checks HTTPS enforcement, legacy protocols, certificate expiry
- **Directory Listing Exposure**: Detects open indexes on sensitive folders (/.git, /backup, /logs)
- **Weak Cookie Detection**: Warns when HttpOnly/Secure/SameSite attributes are missing
- **AI Assistant Quick Fixes**: Auto-prioritized remediation tips accompany every scan

### 📱 Modern Interface
- Responsive design that works on all devices
- Real-time scan progress tracking
- Detailed vulnerability reports with recommendations
- Export results in JSON and HTML formats

### 🚀 Progressive Web App
- Install as a standalone application
- Offline functionality with service worker
- Fast loading and caching

## Installation

### Web Server Setup
1. Copy all files to your web server (Apache, Nginx, or XAMPP)
2. Ensure PHP is installed and configured
3. Access the application via your browser

### Local Development
```bash
# Using XAMPP (as in your setup)
# Files are located at:
/Applications/XAMPP/xamppfiles/htdocs/webapplicationscanner/

# Start Apache server
# Navigate to: http://localhost/webapplicationscanner/
```

### PWA Installation
1. Open the application in a modern browser
2. Click the "Install App" button in the header
3. Follow the browser prompts to install

## Usage

### Basic Scanning
1. Enter the target URL in the input field
2. Select which vulnerability types to scan (any combination of):
   - SQL Injection
   - XSS Vulnerabilities  
   - Authentication Issues
   - Security Headers
   - TLS Configuration
   - Directory Listing
   - Weak Cookies
3. Click "Start Security Scan"
4. Monitor the progress and view results

### Understanding Results
- **Critical/High**: Immediate attention required
- **Medium**: Should be addressed soon
- **Low**: Minor security improvements
- **AI Quick Fix Panel**: Shows top 5 remediation steps ranked by severity and deduplicated across findings

### Export Reports
- **JSON Export**: Machine-readable format for integration
- **HTML Export**: Human-readable report for printing/sharing
- **AI Guidance**: Recommendations are embedded in the UI and can be copied into tickets or follow-up reports

## Technical Details

### Frontend Technologies
- **HTML5**: Modern semantic markup
- **Tailwind CSS**: Utility-first CSS framework
- **Vanilla JavaScript**: No framework dependencies
- **Lucide Icons**: Beautiful icon library

### Backend (PHP)
- **PHP 7.4+**: Server-side scanning logic
- **cURL/HTTP Requests**: Real vulnerability testing
- **JSON API**: RESTful communication

### Security Features
- **Input Validation**: Sanitized URL and parameter handling
- **Error Handling**: Graceful failure management
- **Rate Limiting**: Prevents abuse of the scanner
- **Secure Headers**: Proper security headers

## Scan Types Explained

### SQL Injection
The scanner tests for SQL injection vulnerabilities by:
- Testing common injection payloads
- Analyzing database error messages
- Checking for parameterized query usage

### XSS Detection
Cross-site scripting testing includes:
- Reflected XSS payload injection
- DOM-based XSS patterns
- Content Security Policy analysis

### Security Headers
Validates modern hardening headers:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy
- X-Frame-Options / X-Content-Type-Options
- Referrer-Policy

### TLS Configuration
- Confirms HTTPS enforcement
- Detects legacy TLS 1.0/1.1 negotiations
- Warns about expiring/expired certificates

### Directory Listing
- Crawls common sensitive folders (/backup, /.git, /logs, /uploads)
- Flags when directory indexes expose file listings

### Weak Cookies
- Examines Set-Cookie headers
- Reports missing HttpOnly, Secure, or SameSite flags

### Authentication Issues
Authentication security checks:
- Default credential testing
- Password policy validation
- Session management security
- Brute force protection detection

## Configuration

### Server Requirements
- PHP 7.4 or higher
- Apache/Nginx web server
- cURL extension enabled
- allow_url_fopen enabled

### Browser Requirements
- Modern browser with ES6 support
- JavaScript enabled
- Local storage available

## Security Considerations

⚠️ **Important**: Only scan websites you own or have explicit permission to test.

### Legal Usage
- Use only on authorized targets
- Respect robots.txt and rate limits
- Follow responsible disclosure practices

### Privacy
- No scan data is stored permanently
- All scanning happens in real-time
- Results are only visible to the user

## Troubleshooting

### Common Issues

**"Scan failed" errors**
- Check if target URL is accessible
- Verify PHP extensions are installed
- Ensure server allows external HTTP requests

**AI Assistant not appearing**
- Run at least one scan so the assistant has data to analyze
- Ensure JavaScript is enabled (AI logic runs client-side)
- Look for console errors related to `updateAIAssistant()` in `scanner.js`

**Security header/TLS results look empty**
- Confirm the target URL is reachable over HTTPS
- Some demo scan types use simulated data; wire the frontend to `backend.php` for live checks
- Review browser/network logs to ensure the request isn’t blocked

**PWA installation not working**
- Use a supported browser (Chrome, Edge, Firefox)
- Ensure HTTPS is enabled for production
- Clear browser cache and retry

**Export not working**
- Check browser pop-up blockers
- Ensure JavaScript is enabled
- Try a different browser

### Debug Mode
Enable debug logging by adding to `scanner.js`:
```javascript
// At the top of the file
const DEBUG = true;

// In methods, add:
if (DEBUG) console.log('Debug info:', data);
```

## Testing

Run lightweight checks before deploying:

```bash
# PHP syntax check for backend logic
/Applications/XAMPP/xamppfiles/bin/php -l webapplicationscanner/backend.php

# (Optional) Serve the app via XAMPP/Apache and run a manual smoke test in the browser
``` 

For frontend behavior (progress, AI assistant, exports), open `http://localhost/webapplicationscanner/`, run a sample scan, and verify:
1. Progress bar transitions from 0–100% without errors.
2. Results grid populates with findings covering all enabled modules.
3. AI Assistant panel becomes visible and lists prioritized quick fixes.
4. Toggle new modules (security headers/TLS/dir listing/cookies) to ensure cards are rendered correctly.

## Development

### File Structure
```
webapplicationscanner/
├── index.html          # Main application interface
├── scanner.js          # Frontend scanning logic
├── backend.php         # Server-side vulnerability testing
├── sw.js              # Service worker for PWA
├── manifest.json      # PWA manifest
└── README.md          # This documentation
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

### API Endpoints
- `POST /backend.php`: Perform security scan
- `GET /`: Main application
- `GET /manifest.json`: PWA manifest

## License

This project is provided for educational and authorized security testing purposes. Users are responsible for ensuring compliance with applicable laws and regulations.

## Support

For issues and questions:
1. Check this documentation
2. Review browser console for errors
3. Verify server configuration
4. Test with known vulnerable sites for validation

---

**Disclaimer**: This tool is for authorized security testing only. Users must obtain explicit permission before scanning any website or application.
