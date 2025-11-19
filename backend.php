<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

class SecurityScanner {
    private $targetUrl;
    private $scanTypes;
    
    public function __construct($targetUrl, $scanTypes) {
        $this->targetUrl = $targetUrl;
        $this->scanTypes = $scanTypes;
    }
    
    public function performScan() {
        $results = [];
        
        if (!empty($this->scanTypes['sqlInjection'])) {
            $results = array_merge($results, $this->scanSQLInjection());
        }
        
        if (!empty($this->scanTypes['xss'])) {
            $results = array_merge($results, $this->scanXSS());
        }
        
        if (!empty($this->scanTypes['auth'])) {
            $results = array_merge($results, $this->scanAuthentication());
        }

        if (!empty($this->scanTypes['securityHeaders'])) {
            $results = array_merge($results, $this->scanSecurityHeaders());
        }

        if (!empty($this->scanTypes['tls'])) {
            $results = array_merge($results, $this->scanTLSConfiguration());
        }

        if (!empty($this->scanTypes['dirListing'])) {
            $results = array_merge($results, $this->scanDirectoryListing());
        }

        if (!empty($this->scanTypes['weakCookies'])) {
            $results = array_merge($results, $this->scanWeakCookies());
        }
        
        return [
            'success' => true,
            'results' => $results,
            'summary' => $this->calculateSummary($results)
        ];
    }
    
    private function scanSQLInjection() {
        $vulnerabilities = [];
        $sqlPayloads = [
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
        
        $testUrls = [
            $this->targetUrl . "?id=1",
            $this->targetUrl . "?search=test",
            $this->targetUrl . "?user=admin",
            $this->targetUrl . "?page=1"
        ];
        
        foreach ($testUrls as $baseUrl) {
            foreach ($sqlPayloads as $payload) {
                $testUrl = $baseUrl . $payload;
                if ($this->testSQLInjection($testUrl)) {
                    $vulnerabilities[] = [
                        'type' => 'SQL Injection',
                        'severity' => 'Critical',
                        'url' => $testUrl,
                        'payload' => $payload,
                        'description' => 'Potential SQL injection vulnerability detected',
                        'recommendation' => 'Use parameterized queries and input validation'
                    ];
                }
            }
        }
        
        return $vulnerabilities;
    }
    
    private function scanXSS() {
        $vulnerabilities = [];
        $xssPayloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>'
        ];
        
        $testParams = ['search', 'query', 'q', 'input', 'comment', 'name'];
        
        foreach ($testParams as $param) {
            foreach ($xssPayloads as $payload) {
                $testUrl = $this->targetUrl . "?" . $param . "=" . urlencode($payload);
                if ($this->testXSS($testUrl)) {
                    $vulnerabilities[] = [
                        'type' => 'Cross-Site Scripting (XSS)',
                        'severity' => 'High',
                        'url' => $testUrl,
                        'payload' => $payload,
                        'description' => 'Potential XSS vulnerability detected',
                        'recommendation' => 'Implement proper output encoding and Content Security Policy'
                    ];
                }
            }
        }
        
        return $vulnerabilities;
    }
    
    private function scanAuthentication() {
        $vulnerabilities = [];
        
        $authTests = [
            ['name' => 'Default Credentials', 'severity' => 'High', 'method' => 'testDefaultCredentials'],
            ['name' => 'Weak Password Policy', 'severity' => 'Medium', 'method' => 'testPasswordPolicy'],
            ['name' => 'Session Management', 'severity' => 'Medium', 'method' => 'testSessionManagement'],
            ['name' => 'Brute Force Protection', 'severity' => 'High', 'method' => 'testBruteForceProtection']
        ];
        
        foreach ($authTests as $test) {
            if ($this->$test['method']()) {
                $vulnerabilities[] = [
                    'type' => $test['name'],
                    'severity' => $test['severity'],
                    'url' => $this->targetUrl,
                    'description' => "Authentication issue detected: " . $test['name'],
                    'recommendation' => $this->getAuthRecommendation($test['name'])
                ];
            }
        }
        
        return $vulnerabilities;
    }
    
    private function testSQLInjection($url) {
        $context = stream_context_create([
            'http' => [
                'timeout' => 5,
                'method' => 'GET',
                'ignore_errors' => true
            ]
        ]);
        
        $response = @file_get_contents($url, false, $context);
        
        if ($response === false) {
            return false;
        }
        
        $sqlErrors = [
            'SQL syntax',
            'mysql_fetch',
            'ORA-',
            'Microsoft OLE DB Provider',
            'ODBC Microsoft Access',
            'ODBC SQL Server Driver',
            'SQLServer JDBC Driver',
            'Warning: mysql',
            'Warning: pg_',
            'valid PostgreSQL result',
            'Npgsql\\'
        ];
        
        foreach ($sqlErrors as $error) {
            if (stripos($response, $error) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function testXSS($url) {
        $context = stream_context_create([
            'http' => [
                'timeout' => 5,
                'method' => 'GET',
                'ignore_errors' => true
            ]
        ]);
        
        $response = @file_get_contents($url, false, $context);
        
        if ($response === false) {
            return false;
        }
        
        $xssIndicators = [
            '<script>alert',
            '<img src=x onerror',
            '<svg onload',
            'javascript:',
            '<iframe src="javascript:',
            '<body onload',
            '<input onfocus'
        ];
        
        foreach ($xssIndicators as $indicator) {
            if (stripos($response, $indicator) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function testDefaultCredentials() {
        $commonCredentials = [
            ['admin', 'admin'],
            ['admin', 'password'],
            ['admin', '123456'],
            ['root', 'root'],
            ['root', 'password'],
            ['test', 'test'],
            ['guest', 'guest'],
            ['user', 'user']
        ];
        
        foreach ($commonCredentials as $creds) {
            $loginUrl = $this->targetUrl . "/login";
            $postData = http_build_query([
                'username' => $creds[0],
                'password' => $creds[1]
            ]);
            
            $context = stream_context_create([
                'http' => [
                    'timeout' => 5,
                    'method' => 'POST',
                    'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
                    'content' => $postData,
                    'ignore_errors' => true
                ]
            ]);
            
            $response = @file_get_contents($loginUrl, false, $context);
            
            if ($response && (
                stripos($response, 'welcome') !== false ||
                stripos($response, 'dashboard') !== false ||
                stripos($response, 'logout') !== false
            )) {
                return true;
            }
        }
        
        return false;
    }
    
    private function testPasswordPolicy() {
        $registerUrl = $this->targetUrl . "/register";
        $weakPasswords = ['123', 'password', 'abc', 'test'];
        
        foreach ($weakPasswords as $password) {
            $postData = http_build_query([
                'username' => 'testuser',
                'password' => $password,
                'confirm_password' => $password
            ]);
            
            $context = stream_context_create([
                'http' => [
                    'timeout' => 5,
                    'method' => 'POST',
                    'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
                    'content' => $postData,
                    'ignore_errors' => true
                ]
            ]);
            
            $response = @file_get_contents($registerUrl, false, $context);
            
            if ($response && stripos($response, 'success') !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function testSessionManagement() {
        $context = stream_context_create([
            'http' => [
                'timeout' => 5,
                'method' => 'GET',
                'ignore_errors' => true
            ]
        ]);
        
        $response = @file_get_contents($this->targetUrl, false, $context);
        
        if ($response === false) {
            return false;
        }
        
        $headers = $http_response_header;
        $sessionIssues = [];
        
        foreach ($headers as $header) {
            if (stripos($header, 'Set-Cookie') !== false) {
                if (stripos($header, 'HttpOnly') === false) {
                    return true;
                }
                if (stripos($header, 'Secure') === false && stripos($this->targetUrl, 'https') !== false) {
                    return true;
                }
                if (stripos($header, 'SameSite') === false) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    private function testBruteForceProtection() {
        $loginUrl = $this->targetUrl . "/login";
        $failedAttempts = 0;
        
        for ($i = 0; $i < 10; $i++) {
            $postData = http_build_query([
                'username' => 'invaliduser',
                'password' => 'invalidpass'
            ]);
            
            $context = stream_context_create([
                'http' => [
                    'timeout' => 2,
                    'method' => 'POST',
                    'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
                    'content' => $postData,
                    'ignore_errors' => true
                ]
            ]);
            
            $response = @file_get_contents($loginUrl, false, $context);
            
            if ($response === false) {
                $failedAttempts++;
            }
        }
        
        return $failedAttempts < 8;
    }
    
    private function getAuthRecommendation($issue) {
        $recommendations = [
            'Default Credentials' => 'Change default credentials and enforce strong password policies',
            'Weak Password Policy' => 'Implement strong password requirements and regular password changes',
            'Session Management' => 'Use secure session management with proper timeout and regeneration',
            'Brute Force Protection' => 'Implement rate limiting and account lockout mechanisms'
        ];
        
        return $recommendations[$issue] ?? 'Review and strengthen authentication mechanisms';
    }
    
    private function calculateSummary($results) {
        $summary = [
            'total' => count($results),
            'critical' => 0,
            'medium' => 0,
            'low' => 0
        ];
        
        foreach ($results as $result) {
            switch (strtolower($result['severity'])) {
                case 'critical':
                case 'high':
                    $summary['critical']++;
                    break;
                case 'medium':
                    $summary['medium']++;
                    break;
                case 'low':
                    $summary['low']++;
                    break;
            }
        }
        
        return $summary;
    }

    private function scanSecurityHeaders() {
        $issues = [];
        $headers = @get_headers($this->targetUrl, 1);

        if (!$headers) {
            $issues[] = [
                'type' => 'Security Header Scan',
                'severity' => 'Medium',
                'url' => $this->targetUrl,
                'description' => 'Unable to retrieve response headers to validate security posture',
                'recommendation' => 'Ensure the site is reachable and returns standard HTTP headers.'
            ];
            return $issues;
        }

        $requiredHeaders = [
            'strict-transport-security' => [
                'severity' => 'High',
                'description' => 'Missing Strict-Transport-Security header allows downgrade attacks.',
                'recommendation' => 'Send Strict-Transport-Security with max-age>=31536000 and includeSubDomains.'
            ],
            'content-security-policy' => [
                'severity' => 'High',
                'description' => 'No Content-Security-Policy header detected.',
                'recommendation' => 'Deploy a restrictive Content-Security-Policy to mitigate XSS.'
            ],
            'x-content-type-options' => [
                'severity' => 'Medium',
                'description' => 'X-Content-Type-Options header missing.',
                'recommendation' => 'Return X-Content-Type-Options: nosniff to prevent MIME sniffing.'
            ],
            'x-frame-options' => [
                'severity' => 'Medium',
                'description' => 'X-Frame-Options header missing.',
                'recommendation' => 'Return X-Frame-Options: DENY (or SAMEORIGIN) to block clickjacking.'
            ],
            'referrer-policy' => [
                'severity' => 'Low',
                'description' => 'Referrer-Policy header missing.',
                'recommendation' => 'Set Referrer-Policy to limit sensitive referrer data leakage.'
            ]
        ];

        $normalized = [];
        foreach ($headers as $key => $value) {
            if (is_string($key)) {
                $normalized[strtolower($key)] = $value;
            }
        }

        foreach ($requiredHeaders as $header => $meta) {
            if (!array_key_exists($header, $normalized)) {
                $issues[] = [
                    'type' => 'Missing Security Header',
                    'severity' => $meta['severity'],
                    'url' => $this->targetUrl,
                    'description' => $meta['description'],
                    'recommendation' => $meta['recommendation']
                ];
            }
        }

        return $issues;
    }

    private function scanTLSConfiguration() {
        $issues = [];
        $parts = parse_url($this->targetUrl);

        if (!$parts || empty($parts['host'])) {
            return $issues;
        }

        $scheme = $parts['scheme'] ?? 'http';
        $host = $parts['host'];
        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);

        if ($scheme !== 'https') {
            $issues[] = [
                'type' => 'HTTPS Not Enforced',
                'severity' => 'High',
                'url' => $this->targetUrl,
                'description' => 'Target uses HTTP without transport layer protection.',
                'recommendation' => 'Redirect all traffic to HTTPS and install a trusted TLS certificate.'
            ];
            return $issues;
        }

        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'allow_self_signed' => true
            ]
        ]);

        $client = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $context);

        if (!$client) {
            $issues[] = [
                'type' => 'TLS Handshake Failure',
                'severity' => 'High',
                'url' => $this->targetUrl,
                'description' => 'Unable to negotiate TLS: ' . trim($errstr),
                'recommendation' => 'Verify the TLS certificate, intermediate chain and supported cipher suites.'
            ];
            return $issues;
        }

        $meta = stream_get_meta_data($client);
        if (isset($meta['crypto']['protocol']) && stripos($meta['crypto']['protocol'], 'tlsv1.1') !== false) {
            $issues[] = [
                'type' => 'Legacy TLS Protocol',
                'severity' => 'Medium',
                'url' => $this->targetUrl,
                'description' => 'Server negotiated ' . $meta['crypto']['protocol'] . ', which is outdated.',
                'recommendation' => 'Disable TLS 1.0/1.1 and enforce TLS 1.2+.'
            ];
        }

        $params = stream_context_get_params($client);
        if (!empty($params['options']['ssl']['peer_certificate'])) {
            $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
            if ($cert) {
                $validTo = $cert['validTo_time_t'] ?? null;
                if ($validTo && $validTo < time()) {
                    $issues[] = [
                        'type' => 'Expired TLS Certificate',
                        'severity' => 'High',
                        'url' => $this->targetUrl,
                        'description' => 'The TLS certificate expired on ' . date('c', $validTo) . '.',
                        'recommendation' => 'Renew the TLS certificate immediately.'
                    ];
                } elseif ($validTo && $validTo < strtotime('+30 days')) {
                    $issues[] = [
                        'type' => 'TLS Certificate Expiring Soon',
                        'severity' => 'Medium',
                        'url' => $this->targetUrl,
                        'description' => 'Certificate expires on ' . date('c', $validTo) . '.',
                        'recommendation' => 'Schedule certificate renewal before expiry.'
                    ];
                }
            }
        }

        fclose($client);
        return $issues;
    }

    private function scanDirectoryListing() {
        $issues = [];
        $pathsToTest = ['/', '/backup/', '/.git/', '/uploads/'];
        $base = rtrim($this->targetUrl, '/');

        foreach ($pathsToTest as $path) {
            $url = $base . $path;
            $response = $this->httpRequest($url);

            if ($response['body'] && preg_match('/Index of\s|Directory listing for/i', $response['body'])) {
                $issues[] = [
                    'type' => 'Directory Listing Enabled',
                    'severity' => 'Medium',
                    'url' => $url,
                    'description' => 'Directory listing appears to be enabled exposing the contents of ' . $path,
                    'recommendation' => 'Disable directory indexing via server configuration and restrict direct access.'
                ];
            }
        }

        return $issues;
    }

    private function scanWeakCookies() {
        $issues = [];
        $response = $this->httpRequest($this->targetUrl);
        $setCookies = $this->extractHeaderValues($response['headers'], 'Set-Cookie');

        foreach ($setCookies as $cookie) {
            $missing = [];
            if (stripos($cookie, 'httponly') === false) {
                $missing[] = 'HttpOnly';
            }
            if (stripos($cookie, 'secure') === false && stripos($this->targetUrl, 'https') === 0) {
                $missing[] = 'Secure';
            }
            if (stripos($cookie, 'samesite') === false) {
                $missing[] = 'SameSite';
            }

            if (!empty($missing)) {
                $issues[] = [
                    'type' => 'Weak Cookie Attributes',
                    'severity' => 'Medium',
                    'url' => $this->targetUrl,
                    'description' => 'Cookie missing attributes: ' . implode(', ', $missing),
                    'recommendation' => 'Set ' . implode(', ', $missing) . ' flags on sensitive cookies to mitigate session hijacking.'
                ];
            }
        }

        return $issues;
    }

    private function httpRequest($url, $options = []) {
        $method = strtoupper($options['method'] ?? 'GET');
        $timeout = $options['timeout'] ?? 8;
        $headers = $options['header'] ?? '';
        $content = $options['content'] ?? null;

        $context = stream_context_create([
            'http' => array_filter([
                'method' => $method,
                'timeout' => $timeout,
                'ignore_errors' => true,
                'header' => $headers,
                'content' => $content
            ])
        ]);

        $body = @file_get_contents($url, false, $context);
        $responseHeaders = $http_response_header ?? [];

        return [
            'body' => $body,
            'headers' => $responseHeaders,
            'status' => $this->extractStatusCode($responseHeaders)
        ];
    }

    private function extractStatusCode($headers) {
        if (!$headers) {
            return null;
        }

        $statusLine = $headers[0] ?? '';
        if (preg_match('/\s(\d{3})\s/', $statusLine, $matches)) {
            return (int) $matches[1];
        }

        return null;
    }

    private function extractHeaderValues($headers, $name) {
        $values = [];
        foreach ($headers as $header) {
            if (stripos($header, $name . ':') === 0) {
                $values[] = trim(substr($header, strlen($name) + 1));
            }
        }
        return $values;
    }
}

try {
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!$input || !isset($input['targetUrl'])) {
        throw new Exception('Missing target URL');
    }
    
    $targetUrl = filter_var($input['targetUrl'], FILTER_SANITIZE_URL);
    $scanTypes = $input['scanTypes'] ?? [
        'sqlInjection' => true,
        'xss' => true,
        'auth' => true,
        'securityHeaders' => true,
        'tls' => true,
        'dirListing' => true,
        'weakCookies' => true
    ];
    
    if (!filter_var($targetUrl, FILTER_VALIDATE_URL)) {
        throw new Exception('Invalid URL format');
    }
    
    $scanner = new SecurityScanner($targetUrl, $scanTypes);
    $result = $scanner->performScan();
    
    echo json_encode($result);
    
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
?>
