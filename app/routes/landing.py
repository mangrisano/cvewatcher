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
    </head>
    <body class="bg-gray-50">
        <!-- Navigation -->
        <nav class="bg-white shadow-lg">
            <div class="container mx-auto px-6 py-3">
                <div class="flex justify-between items-center">
                    <div class="flex items-center">
                        <i class="fas fa-shield-alt text-blue-600 text-2xl mr-3"></i>
                        <span class="text-xl font-bold text-gray-800">CVE Watcher</span>
                    </div>
                    <div class="space-x-4">
                        <a href="/dashboard" class="text-gray-600 hover:text-blue-600">Dashboard</a>
                        <a href="/docs" class="text-gray-600 hover:text-blue-600">API Docs</a>
                        <a href="#pricing" class="text-gray-600 hover:text-blue-600">Pricing</a>
                        <button onclick="window.location.href='/dashboard'" class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">
                            Sign in
                        </button>
                    </div>
                </div>
            </div>
        </nav>

        <!-- Hero Section -->
        <section class="bg-gradient-to-r from-blue-600 to-purple-600 text-white py-20">
            <div class="container mx-auto px-6 text-center">
                <h1 class="text-5xl font-bold mb-6">
                    Monitor Your Software Vulnerabilities<br>
                    <span class="text-yellow-300">Before Attackers Do</span>
                </h1>
                <p class="text-xl mb-8 max-w-3xl mx-auto">
                    Automated CVE monitoring for your entire software stack. 
                    Get alerted instantly when new vulnerabilities affect your assets.
                </p>
                <div class="space-x-4">
                    <button onclick="window.open('/docs', '_blank')" class="bg-yellow-400 text-gray-900 px-8 py-3 rounded-lg font-semibold hover:bg-yellow-300 transition">
                        <i class="fas fa-rocket mr-2"></i>Start Free Trial
                    </button>
                    <button onclick="document.getElementById('demo').scrollIntoView({behavior: 'smooth'})" class="border-2 border-white px-8 py-3 rounded-lg font-semibold hover:bg-white hover:text-gray-900 transition">
                        <i class="fas fa-play mr-2"></i>View Demo
                    </button>
                </div>
                <div class="mt-12">
                    <p class="text-sm opacity-75 mb-4">Trusted by developers worldwide</p>
                    <div class="flex justify-center items-center space-x-8 opacity-60">
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
        <section class="py-20 bg-gray-50">
            <div class="container mx-auto px-6">
                <h2 class="text-4xl font-bold text-center mb-16 text-gray-800">Why Choose CVE Watcher?</h2>
                <div class="grid md:grid-cols-3 gap-8">
                    <div class="bg-white p-8 rounded-lg shadow-lg text-center hover:shadow-xl transition">
                        <div class="text-4xl mb-4 text-blue-600"><i class="fas fa-search"></i></div>
                        <h3 class="text-xl font-semibold mb-4">Real-time Monitoring</h3>
                        <p class="text-gray-600">Instant alerts when new CVEs affect your software assets. Never miss a critical vulnerability again.</p>
                    </div>
                    <div class="bg-white p-8 rounded-lg shadow-lg text-center hover:shadow-xl transition">
                        <div class="text-4xl mb-4 text-green-600"><i class="fas fa-chart-line"></i></div>
                        <h3 class="text-xl font-semibold mb-4">Risk Assessment</h3>
                        <p class="text-gray-600">Severity-based prioritization helps you focus on the most critical vulnerabilities first.</p>
                    </div>
                    <div class="bg-white p-8 rounded-lg shadow-lg text-center hover:shadow-xl transition">
                        <div class="text-4xl mb-4 text-purple-600"><i class="fas fa-cogs"></i></div>
                        <h3 class="text-xl font-semibold mb-4">Easy Integration</h3>
                        <p class="text-gray-600">REST API with comprehensive documentation. Integrate with your existing security tools.</p>
                    </div>
                    <div class="bg-white p-8 rounded-lg shadow-lg text-center hover:shadow-xl transition">
                        <div class="text-4xl mb-4 text-red-600"><i class="fas fa-shield-alt"></i></div>
                        <h3 class="text-xl font-semibold mb-4">Enterprise Security</h3>
                        <p class="text-gray-600">JWT authentication, HTTPS enforcement, and security headers built-in.</p>
                    </div>
                    <div class="bg-white p-8 rounded-lg shadow-lg text-center hover:shadow-xl transition">
                        <div class="text-4xl mb-4 text-yellow-600"><i class="fas fa-file-alt"></i></div>
                        <h3 class="text-xl font-semibold mb-4">Compliance Reports</h3>
                        <p class="text-gray-600">Generate audit-ready reports for compliance frameworks and security assessments.</p>
                    </div>
                    <div class="bg-white p-8 rounded-lg shadow-lg text-center hover:shadow-xl transition">
                        <div class="text-4xl mb-4 text-indigo-600"><i class="fab fa-docker"></i></div>
                        <h3 class="text-xl font-semibold mb-4">Cloud Ready</h3>
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
                    <div class="bg-gray-900 rounded-lg p-6 text-green-400 font-mono text-sm">
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

        <!-- Pricing Section -->
        <section id="pricing" class="py-20 bg-gray-50">
            <div class="container mx-auto px-6">
                <h2 class="text-4xl font-bold text-center mb-16 text-gray-800">Simple, Transparent Pricing</h2>
                <div class="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
                    <!-- Free Tier -->
                    <div class="bg-white p-8 rounded-lg shadow-lg">
                        <h3 class="text-2xl font-bold mb-4">Starter</h3>
                        <div class="text-4xl font-bold mb-4">Free</div>
                        <p class="text-gray-600 mb-6">Perfect for small projects</p>
                        <ul class="space-y-3 mb-8">
                            <li class="flex items-center">
                                <i class="fas fa-check text-green-500 mr-3"></i>
                                <span>5 assets monitored</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check text-green-500 mr-3"></i>
                                <span>Daily CVE updates</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check text-green-500 mr-3"></i>
                                <span>Email notifications</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check text-green-500 mr-3"></i>
                                <span>REST API access</span>
                            </li>
                        </ul>
                        <button onclick="window.open('/docs', '_blank')" class="w-full border-2 border-blue-600 text-blue-600 py-3 rounded-lg font-semibold hover:bg-blue-600 hover:text-white transition">
                            Get Started
                        </button>
                    </div>

                    <!-- Professional Tier -->
                    <div class="bg-blue-600 text-white p-8 rounded-lg shadow-lg transform scale-105">
                        <div class="bg-yellow-400 text-gray-900 text-sm px-3 py-1 rounded-full inline-block mb-4">
                            Most Popular
                        </div>
                        <h3 class="text-2xl font-bold mb-4">Professional</h3>
                        <div class="text-4xl font-bold mb-4">$29<span class="text-lg">/mo</span></div>
                        <p class="mb-6">For growing teams</p>
                        <ul class="space-y-3 mb-8">
                            <li class="flex items-center">
                                <i class="fas fa-check text-yellow-400 mr-3"></i>
                                <span>100 assets monitored</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check text-yellow-400 mr-3"></i>
                                <span>Real-time CVE updates</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check text-yellow-400 mr-3"></i>
                                <span>Slack/Teams integration</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check text-yellow-400 mr-3"></i>
                                <span>Advanced reporting</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check text-yellow-400 mr-3"></i>
                                <span>Priority support</span>
                            </li>
                        </ul>
                        <button class="w-full bg-yellow-400 text-gray-900 py-3 rounded-lg font-semibold hover:bg-yellow-300 transition">
                            Start Free Trial
                        </button>
                    </div>

                    <!-- Enterprise Tier -->
                    <div class="bg-white p-8 rounded-lg shadow-lg">
                        <h3 class="text-2xl font-bold mb-4">Enterprise</h3>
                        <div class="text-4xl font-bold mb-4">Custom</div>
                        <p class="text-gray-600 mb-6">For large organizations</p>
                        <ul class="space-y-3 mb-8">
                            <li class="flex items-center">
                                <i class="fas fa-check text-green-500 mr-3"></i>
                                <span>Unlimited assets</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check text-green-500 mr-3"></i>
                                <span>Custom integrations</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check text-green-500 mr-3"></i>
                                <span>On-premise deployment</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check text-green-500 mr-3"></i>
                                <span>24/7 dedicated support</span>
                            </li>
                            <li class="flex items-center">
                                <i class="fas fa-check text-green-500 mr-3"></i>
                                <span>SLA guarantee</span>
                            </li>
                        </ul>
                        <button class="w-full border-2 border-gray-300 text-gray-700 py-3 rounded-lg font-semibold hover:border-blue-600 hover:text-blue-600 transition">
                            Contact Sales
                        </button>
                    </div>
                </div>
            </div>
        </section>

        <!-- CTA Section -->
        <section class="py-20 bg-gradient-to-r from-blue-600 to-purple-600 text-white">
            <div class="container mx-auto px-6 text-center">
                <h2 class="text-4xl font-bold mb-6">Ready to Secure Your Software Stack?</h2>
                <p class="text-xl mb-8 max-w-2xl mx-auto">
                    Join thousands of developers who trust CVE Watcher to keep their applications secure.
                </p>
                <div class="space-x-4">
                    <button onclick="window.open('/docs', '_blank')" class="bg-yellow-400 text-gray-900 px-8 py-3 rounded-lg font-semibold hover:bg-yellow-300 transition">
                        <i class="fas fa-rocket mr-2"></i>Start Free Today
                    </button>
                    <button class="border-2 border-white px-8 py-3 rounded-lg font-semibold hover:bg-white hover:text-gray-900 transition">
                        <i class="fas fa-phone mr-2"></i>Schedule Demo
                    </button>
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
                            Automated vulnerability monitoring for modern software teams.
                        </p>
                    </div>
                    <div>
                        <h4 class="font-semibold mb-4">Product</h4>
                        <ul class="space-y-2 text-gray-400">
                            <li><a href="/docs" class="hover:text-white">API Documentation</a></li>
                            <li><a href="#" class="hover:text-white">Features</a></li>
                            <li><a href="#pricing" class="hover:text-white">Pricing</a></li>
                        </ul>
                    </div>
                    <div>
                        <h4 class="font-semibold mb-4">Support</h4>
                        <ul class="space-y-2 text-gray-400">
                            <li><a href="#" class="hover:text-white">Help Center</a></li>
                            <li><a href="#" class="hover:text-white">Contact Us</a></li>
                            <li><a href="#" class="hover:text-white">Status Page</a></li>
                        </ul>
                    </div>
                    <div>
                        <h4 class="font-semibold mb-4">Legal</h4>
                        <ul class="space-y-2 text-gray-400">
                            <li><a href="#" class="hover:text-white">Privacy Policy</a></li>
                            <li><a href="#" class="hover:text-white">Terms of Service</a></li>
                            <li><a href="#" class="hover:text-white">Security</a></li>
                        </ul>
                    </div>
                </div>
                <div class="border-t border-gray-800 mt-8 pt-8 text-center">
                    <p class="text-gray-400">
                        © 2025 CVE Watcher. All rights reserved. | 
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
