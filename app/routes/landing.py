from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/", response_class=HTMLResponse, tags=["landing"])
async def landing_page():
    """Landing page for CVE Watcher SaaS"""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CVE Watcher - Automated Vulnerability Monitoring</title>
        <meta name="description" content="Monitor your software vulnerabilities before attackers do. Automated CVE monitoring for your entire software stack.">
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            .hero-section {
                background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 50%, #db2777 100%);
                background-color: #4f46e5;
            }
            .hero-pattern {
                background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.08'%3E%3Ccircle cx='30' cy='30' r='4'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
            }
            .card-hover {
                transition: transform 0.3s ease, box-shadow 0.3s ease;
            }
            .card-hover:hover {
                transform: translateY(-5px);
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            }
        </style>
    </head>
    <body class="bg-gray-50">
        <!-- Navigation -->
        <nav class="bg-white shadow-lg sticky top-0 z-50">
            <div class="container mx-auto px-6 py-3">
                <div class="flex justify-between items-center">
                    <div class="flex items-center">
                        <i class="fas fa-shield-alt text-blue-600 text-2xl mr-3"></i>
                        <span class="text-xl font-bold text-gray-800">CVE Watcher</span>
                    </div>
                    <div class="hidden md:flex items-center space-x-6">
                        <a href="#features" class="text-gray-600 hover:text-blue-600 transition">Features</a>
                        <a href="#demo" class="text-gray-600 hover:text-blue-600 transition">Demo</a>
                        <a href="#opensource" class="text-gray-600 hover:text-blue-600 transition">Open Source</a>
                        <a href="/dashboard" class="text-gray-600 hover:text-blue-600 transition">Dashboard</a>
                        <a href="/docs" class="text-gray-600 hover:text-blue-600 transition">API Docs</a>
                        <a href="https://github.com/mangrisano/cvewatcher" class="text-gray-600 hover:text-blue-600 transition" title="GitHub"><i class="fab fa-github text-xl"></i></a>
                        <button onclick="window.location.href='/dashboard'" class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition">
                            Sign in
                        </button>
                    </div>
                </div>
            </div>
        </nav>

        <!-- Hero Section -->
        <section class="hero-section hero-pattern text-white py-24">
            <div class="container mx-auto px-6 text-center">
                <h1 class="text-5xl font-bold mb-6">
                    Monitor Your Software Vulnerabilities<br>
                    <span class="text-yellow-300">Before Attackers Do</span>
                </h1>
                <p class="text-xl mb-8 max-w-3xl mx-auto opacity-90">
                    Automated CVE monitoring for your entire software stack.
                    Get alerted instantly when new vulnerabilities affect your assets.
                </p>
                <div class="flex flex-col sm:flex-row gap-4 justify-center">
                    <a href="https://github.com/mangrisano/cvewatcher" class="bg-yellow-400 text-blue-900 px-8 py-4 rounded-lg text-lg font-semibold hover:bg-yellow-300 transition">
                        <i class="fab fa-github mr-2"></i>View on GitHub
                    </a>
                    <a href="#demo" class="border-2 border-white px-8 py-4 rounded-lg text-lg font-semibold hover:bg-white hover:text-blue-900 transition">
                        <i class="fas fa-play mr-2"></i>Watch Demo
                    </a>
                </div>
                <div class="mt-12">
                    <p class="text-sm opacity-75 mb-4">Free and open source &mdash; self-host with Docker in minutes</p>
                    <div class="flex justify-center items-center space-x-8 opacity-70">
                        <div class="text-2xl"><i class="fab fa-github"></i> GitHub</div>
                        <div class="text-2xl"><i class="fab fa-docker"></i> Docker</div>
                        <div class="text-2xl"><i class="fas fa-cloud"></i> Cloud Ready</div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Problem/Solution Section -->
        <section class="py-20 bg-white">
            <div class="container mx-auto px-6">
                <div class="grid md:grid-cols-2 gap-12 items-center">
                    <div>
                        <h2 class="text-4xl font-bold text-gray-800 mb-6">
                            <span class="text-red-500">73%</span> of organizations don't know when their software has vulnerabilities
                        </h2>
                        <p class="text-lg text-gray-600 mb-6">
                            New CVEs are discovered daily, but most teams only find out about them through security incidents or manual checks.
                        </p>
                        <ul class="space-y-3">
                            <li class="flex items-center">
                                <i class="fas fa-times-circle text-red-500 mr-3"></i>
                                <span>Manual vulnerability tracking</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-times-circle text-red-500 mr-3"></i>
                                <span>Delayed security notifications</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-times-circle text-red-500 mr-3"></i>
                                <span>Incomplete asset inventory</span>
                            </li>
                        </ul>
                    </div>
                    <div class="bg-gray-100 p-8 rounded-lg">
                        <h3 class="text-2xl font-bold text-gray-800 mb-4">
                            <i class="fas fa-lightbulb text-yellow-500 mr-2"></i>Our Solution
                        </h3>
                        <p class="text-gray-600 mb-6">
                            CVE Watcher automatically monitors your software inventory against the latest CVE database and alerts you instantly.
                        </p>
                        <ul class="space-y-3">
                            <li class="flex items-center">
                                <i class="fas fa-check-circle text-green-500 mr-3"></i>
                                <span>Automated 24/7 monitoring</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check-circle text-green-500 mr-3"></i>
                                <span>Real-time vulnerability alerts</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check-circle text-green-500 mr-3"></i>
                                <span>Complete asset management</span>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </section>

        <!-- Features Section -->
        <section id="features" class="py-20 bg-gray-50">
            <div class="container mx-auto px-6">
                <div class="text-center mb-16">
                    <h2 class="text-4xl font-bold text-gray-900 mb-4">Why Choose CVE Watcher?</h2>
                    <p class="text-xl text-gray-600 max-w-3xl mx-auto">Stay ahead of security threats with comprehensive vulnerability monitoring.</p>
                </div>
                <div class="grid md:grid-cols-3 gap-8">
                    <div class="text-center p-8 bg-white rounded-xl shadow-sm card-hover">
                        <div class="bg-blue-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6">
                            <i class="fas fa-search text-blue-600 text-2xl"></i>
                        </div>
                        <h3 class="text-xl font-semibold mb-4 text-gray-900">Real-time Monitoring</h3>
                        <p class="text-gray-600">Instant alerts when new CVEs affect your software assets. Never miss a critical vulnerability again.</p>
                    </div>
                    <div class="text-center p-8 bg-white rounded-xl shadow-sm card-hover">
                        <div class="bg-green-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6">
                            <i class="fas fa-chart-line text-green-600 text-2xl"></i>
                        </div>
                        <h3 class="text-xl font-semibold mb-4 text-gray-900">Risk Assessment</h3>
                        <p class="text-gray-600">Severity-based prioritization helps you focus on the most critical vulnerabilities first.</p>
                    </div>
                    <div class="text-center p-8 bg-white rounded-xl shadow-sm card-hover">
                        <div class="bg-purple-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6">
                            <i class="fas fa-cogs text-purple-600 text-2xl"></i>
                        </div>
                        <h3 class="text-xl font-semibold mb-4 text-gray-900">Easy Integration</h3>
                        <p class="text-gray-600">REST API with comprehensive documentation. Integrate with your existing security tools.</p>
                    </div>
                    <div class="text-center p-8 bg-white rounded-xl shadow-sm card-hover">
                        <div class="bg-red-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6">
                            <i class="fas fa-shield-alt text-red-600 text-2xl"></i>
                        </div>
                        <h3 class="text-xl font-semibold mb-4 text-gray-900">Enterprise Security</h3>
                        <p class="text-gray-600">JWT authentication, HTTPS enforcement, and security headers built-in.</p>
                    </div>
                    <div class="text-center p-8 bg-white rounded-xl shadow-sm card-hover">
                        <div class="bg-yellow-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6">
                            <i class="fas fa-file-alt text-yellow-600 text-2xl"></i>
                        </div>
                        <h3 class="text-xl font-semibold mb-4 text-gray-900">Compliance Reports</h3>
                        <p class="text-gray-600">Generate audit-ready reports for compliance frameworks and security assessments.</p>
                    </div>
                    <div class="text-center p-8 bg-white rounded-xl shadow-sm card-hover">
                        <div class="bg-indigo-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6">
                            <i class="fab fa-docker text-indigo-600 text-2xl"></i>
                        </div>
                        <h3 class="text-xl font-semibold mb-4 text-gray-900">Cloud Ready</h3>
                        <p class="text-gray-600">Dockerized deployment with PostgreSQL. Scale from startup to enterprise.</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Demo Section -->
        <section id="demo" class="py-20 bg-white">
            <div class="container mx-auto px-6">
                <h2 class="text-4xl font-bold text-center mb-16 text-gray-800">See CVE Watcher in Action</h2>
                <div class="max-w-4xl mx-auto">
                    <div class="bg-gray-900 rounded-xl p-6 text-green-400 font-mono text-sm shadow-xl">
                        <div class="flex items-center mb-4">
                            <div class="flex space-x-2 mr-4">
                                <div class="w-3 h-3 bg-red-500 rounded-full"></div>
                                <div class="w-3 h-3 bg-yellow-500 rounded-full"></div>
                                <div class="w-3 h-3 bg-green-500 rounded-full"></div>
                            </div>
                            <span class="text-gray-400">CVE Watcher Demo Terminal</span>
                        </div>
                        <div class="mb-4">
                            <span class="text-yellow-400">$</span> curl -X POST "http://localhost:8000/auth/login" \\<br>
                            &nbsp;&nbsp;-H "Content-Type: application/json" \\<br>
                            &nbsp;&nbsp;-d '{"email": "demo@example.com", "password": "demo123"}'
                        </div>
                        <div class="mb-4 text-blue-400">
                            {<br>
                            &nbsp;&nbsp;"message": "Login successful",<br>
                            &nbsp;&nbsp;"access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",<br>
                            &nbsp;&nbsp;"token_type": "bearer"<br>
                            }
                        </div>
                        <div class="mb-4">
                            <span class="text-yellow-400">$</span> curl -X GET "http://localhost:8000/assets/vulnerabilities" \\<br>
                            &nbsp;&nbsp;-H "Authorization: Bearer YOUR_TOKEN"
                        </div>
                        <div class="text-blue-400">
                            {<br>
                            &nbsp;&nbsp;"vulnerabilities": [<br>
                            &nbsp;&nbsp;&nbsp;&nbsp;{<br>
                            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"cve_id": "CVE-2024-1234",<br>
                            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"severity": "CRITICAL",<br>
                            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"score": 9.8,<br>
                            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"summary": "Remote code execution in Apache..."<br>
                            &nbsp;&nbsp;&nbsp;&nbsp;}<br>
                            &nbsp;&nbsp;]<br>
                            }
                        </div>
                    </div>
                    <div class="text-center mt-8">
                        <button onclick="window.open('/docs', '_blank')" class="bg-blue-600 text-white px-8 py-3 rounded-lg font-semibold hover:bg-blue-700 transition">
                            <i class="fas fa-code mr-2"></i>Try Interactive API Docs
                        </button>
                    </div>
                </div>
            </div>
        </section>

        <!-- Open Source Section -->
        <section id="opensource" class="py-20 bg-gray-50">
            <div class="container mx-auto px-6">
                <div class="text-center mb-12">
                    <span class="inline-block bg-green-100 text-green-700 text-sm font-semibold px-4 py-1 rounded-full mb-4">
                        100% Free &amp; Open Source
                    </span>
                    <h2 class="text-4xl font-bold text-gray-900 mb-4">No plans. No paywalls. Just self-host it.</h2>
                    <p class="text-xl text-gray-600 max-w-3xl mx-auto">
                        CVE Watcher is released under the MIT license. Run it on your own
                        infrastructure with Docker &mdash; all features included, no limits.
                    </p>
                </div>
                <div class="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
                    <div class="text-center p-8 bg-white rounded-xl shadow-sm card-hover">
                        <div class="bg-blue-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6">
                            <i class="fab fa-github text-blue-600 text-2xl"></i>
                        </div>
                        <h3 class="text-xl font-semibold mb-3 text-gray-900">MIT Licensed</h3>
                        <p class="text-gray-600">Use it, modify it, deploy it commercially. The full source is on GitHub.</p>
                    </div>
                    <div class="text-center p-8 bg-white rounded-xl shadow-sm card-hover">
                        <div class="bg-green-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6">
                            <i class="fab fa-docker text-green-600 text-2xl"></i>
                        </div>
                        <h3 class="text-xl font-semibold mb-3 text-gray-900">Self-Hosted</h3>
                        <p class="text-gray-600">Spin it up with Docker Compose in minutes. Your data stays on your servers.</p>
                    </div>
                    <div class="text-center p-8 bg-white rounded-xl shadow-sm card-hover">
                        <div class="bg-purple-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6">
                            <i class="fas fa-infinity text-purple-600 text-2xl"></i>
                        </div>
                        <h3 class="text-xl font-semibold mb-3 text-gray-900">No Limits</h3>
                        <p class="text-gray-600">Unlimited assets and monitoring. No tiers, no per-seat pricing, no SLA upsell.</p>
                    </div>
                </div>
                <div class="text-center mt-12 flex flex-col sm:flex-row gap-4 justify-center">
                    <a href="https://github.com/mangrisano/cvewatcher" class="bg-gray-900 text-white px-8 py-4 rounded-lg text-lg font-semibold hover:bg-gray-800 transition">
                        <i class="fab fa-github mr-2"></i>View on GitHub
                    </a>
                    <a href="/docs" class="border-2 border-gray-900 text-gray-900 px-8 py-4 rounded-lg text-lg font-semibold hover:bg-gray-900 hover:text-white transition">
                        <i class="fas fa-book mr-2"></i>Read the API Docs
                    </a>
                </div>
            </div>
        </section>

        <!-- CTA Section -->
        <section class="py-20 hero-section text-white">
            <div class="container mx-auto px-6 text-center">
                <h2 class="text-4xl font-bold mb-6">Ready to Secure Your Software Stack?</h2>
                <p class="text-xl mb-8 max-w-2xl mx-auto">
                    Clone the repo, run it with Docker, and start monitoring your assets today.
                </p>
                <div class="flex flex-col sm:flex-row gap-4 justify-center">
                    <a href="https://github.com/mangrisano/cvewatcher" class="bg-yellow-400 text-gray-900 px-8 py-3 rounded-lg font-semibold hover:bg-yellow-300 transition">
                        <i class="fab fa-github mr-2"></i>Get the Source
                    </a>
                    <a href="/docs" class="border-2 border-white px-8 py-3 rounded-lg font-semibold hover:bg-white hover:text-gray-900 transition">
                        <i class="fas fa-book mr-2"></i>Read the Docs
                    </a>
                </div>
            </div>
        </section>

        <!-- Footer -->
        <footer class="bg-gray-900 text-white py-12">
            <div class="container mx-auto px-6">
                <div class="grid md:grid-cols-4 gap-8">
                    <div>
                        <div class="flex items-center mb-4">
                            <i class="fas fa-shield-alt text-blue-400 text-2xl mr-3"></i>
                            <span class="text-xl font-bold">CVE Watcher</span>
                        </div>
                        <p class="text-gray-400">
                            Open-source, self-hosted vulnerability monitoring for your software stack.
                        </p>
                    </div>
                    <div>
                        <h4 class="font-semibold mb-4">Product</h4>
                        <ul class="space-y-2 text-gray-400">
                            <li><a href="/docs" class="hover:text-white">API Documentation</a></li>
                            <li><a href="#features" class="hover:text-white">Features</a></li>
                            <li><a href="#opensource" class="hover:text-white">Open Source</a></li>
                        </ul>
                    </div>
                    <div>
                        <h4 class="font-semibold mb-4">Resources</h4>
                        <ul class="space-y-2 text-gray-400">
                            <li><a href="https://github.com/mangrisano/cvewatcher" class="hover:text-white">GitHub Repository</a></li>
                            <li><a href="https://github.com/mangrisano/cvewatcher/issues" class="hover:text-white">Report an Issue</a></li>
                            <li><a href="/dashboard" class="hover:text-white">Dashboard</a></li>
                        </ul>
                    </div>
                    <div>
                        <h4 class="font-semibold mb-4">Legal</h4>
                        <ul class="space-y-2 text-gray-400">
                            <li><a href="https://github.com/mangrisano/cvewatcher/blob/main/LICENSE" class="hover:text-white">MIT License</a></li>
                        </ul>
                    </div>
                </div>
                <div class="border-t border-gray-800 mt-8 pt-8 text-center">
                    <p class="text-gray-400">
                        © 2026 CVE Watcher. MIT Licensed. | 
                        <a href="https://github.com/mangrisano/cvewatcher" class="hover:text-white">
                            <i class="fab fa-github mr-1"></i>Open Source
                        </a>
                    </p>
                </div>
            </div>
        </footer>

        <script>
            // Simple analytics placeholder
            console.log('CVE Watcher Landing Page Loaded');
            
            // Smooth scrolling for anchor links
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    document.querySelector(this.getAttribute('href')).scrollIntoView({
                        behavior: 'smooth'
                    });
                });
            });
        </script>
    </body>
    </html>
    """
