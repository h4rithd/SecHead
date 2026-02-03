import argparse
import requests
import sys
import re
from urllib.parse import urlparse
from datetime import datetime

# --- Configuration ---

SECURITY_HEADERS = {
    'Content-Security-Policy': {
        'risk': 'High',
        'rec': "Define approved sources. Avoid 'unsafe-inline' & 'unsafe-eval'.",
        'desc': "Restricts the sources of executable scripts, images, and styles to prevent XSS attacks.",
        'best': "default-src 'self'; script-src 'self' https://trusted.com",
        'check': lambda v: 'unsafe-inline' in v or 'unsafe-eval' in v or v.strip() == ''
    },
    'Strict-Transport-Security': {
        'risk': 'High',
        'rec': 'Enforce HTTPS. Set max-age to > 31536000 (1 year).',
        'desc': "Forces the browser to communicate only via HTTPS, preventing Man-in-the-Middle attacks.",
        'best': "max-age=63072000; includeSubDomains; preload",
        'check': lambda v: 'max-age' not in v or int(re.search(r'max-age=(\d+)', v).group(1)) < 31536000
    },
    'X-Content-Type-Options': {
        'risk': 'Medium',
        'rec': "Set to 'nosniff' to prevent MIME sniffing.",
        'desc': "Prevents the browser from 'sniffing' the response type, stopping attacks where scripts are disguised as images.",
        'best': "nosniff",
        'check': lambda v: v.lower() != 'nosniff'
    },
    'X-Frame-Options': {
        'risk': 'Medium',
        'rec': "Set to 'DENY' or 'SAMEORIGIN' to prevent Clickjacking.",
        'desc': "Controls whether the browser is allowed to render the page in an <iframe, protecting against Clickjacking.",
        'best': "DENY or SAMEORIGIN",
        'check': lambda v: v.upper() not in ['DENY', 'SAMEORIGIN']
    },
    'Referrer-Policy': {
        'risk': 'Low',
        'rec': "Set to 'strict-origin-when-cross-origin' or 'no-referrer'.",
        'desc': "Controls how much information about the current page is sent to the next page when a user clicks a link.",
        'best': "strict-origin-when-cross-origin",
        'check': lambda v: 'unsafe-url' in v
    },
    'Permissions-Policy': {
        'risk': 'Low',
        'rec': "Explicitly disable sensitive features like camera, microphone, and geolocation if not used.",
        'desc': "Allows you to enable or disable browser features and APIs (e.g., camera, microphone, geolocation) for your site.",
        'best': "camera=(), microphone=(), geolocation=()",
        'check': lambda v: v.strip() == '' or ('camera' not in v and 'microphone' not in v and 'geolocation' not in v)
    }
}

INFO_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']

# Patterns to look for in Headers, Cookies, or Body
SIGS = {
    'PHP': {'headers': [r'X-Powered-By: PHP'], 'cookies': [r'PHPSESSID']},
    'ASP.NET / IIS': {
        'headers': [r'X-AspNet-Version', r'X-Powered-By: ASP.NET', r'Server: Microsoft-IIS'], 
        'cookies': [r'ASP.NET_SessionId', r'__VIEWSTATE'],
        'body': [r'403 - Forbidden: Access is denied', r'Server Error in .* Application', r'font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;']
    },
    'Java': {'cookies': [r'JSESSIONID']},
    'Nginx': {'headers': [r'Server: nginx']},
    'Apache': {'headers': [r'Server: Apache']},
    'Express': {'headers': [r'X-Powered-By: Express']},
    'Django': {'cookies': [r'csrftoken']},
    'Laravel': {'cookies': [r'laravel_session']}
}

def construct_raw_request(req):
    url_parts = urlparse(req.url)
    path = url_parts.path if url_parts.path else '/'
    if url_parts.query:
        path += '?' + url_parts.query
    raw = f"{req.method} {path} HTTP/1.1\n"
    for k, v in req.headers.items():
        raw += f"{k}: {v}\n"
    if req.body:
        raw += "\n" + str(req.body)
    return raw

def construct_raw_response(res):
    protocol = "HTTP/1.1"
    if res.raw.version == 20: protocol = "HTTP/2"
    raw = f"{protocol} {res.status_code} {res.reason}\n"
    for k, v in res.headers.items():
        raw += f"{k}: {v}\n"
    raw += "\n"
    raw += res.text[:2000] 
    if len(res.text) > 2000:
        raw += "\n...[truncated]..."
    return raw

def analyze_target(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        response = requests.get(url, headers=headers, timeout=15, verify=False, allow_redirects=True)
        
        # 1. Analyze Security Headers
        results = {}
        for header, info in SECURITY_HEADERS.items():
            value = response.headers.get(header)
            # Case insensitive lookup
            if not value:
                for h in response.headers:
                    if h.lower() == header.lower():
                        value = response.headers[h]
                        break
            
            status = "MISSING"
            msg = "Header is missing entirely."
            
            if value:
                is_misconfigured = info['check'](value)
                if is_misconfigured:
                    status = "MISCONFIGURED"
                    if header == 'Content-Security-Policy':
                        msg = "Policy contains 'unsafe-inline', 'unsafe-eval', or is too broad."
                    elif header == 'Strict-Transport-Security':
                        msg = "max-age is missing or too short (less than 1 year)."
                    elif header == 'X-Content-Type-Options':
                        msg = "Value is not 'nosniff'."
                    elif header == 'X-Frame-Options':
                        msg = "Value allows framing (not DENY or SAMEORIGIN)."
                    elif header == 'Referrer-Policy':
                        msg = "Policy 'unsafe-url' leaks full URLs to third parties."
                    elif header == 'Permissions-Policy':
                        msg = "Sensitive features (camera/mic/geo) are not explicitly disabled."
                    else:
                        msg = "Value is potentially unsafe."
                else:
                    status = "OK"
                    msg = "Configuration looks secure."
            
            results[header] = {
                'status': status,
                'value': value or 'N/A',
                'msg': msg,
                'rec': info['rec'],
                'desc': info['desc'], 
                'best': info['best']
            }

        # 2. Clickjacking Specific Check
        x_frame = results.get('X-Frame-Options', {})
        csp = results.get('Content-Security-Policy', {})
        
        cj_vulnerable = False
        cj_reasons = []

        x_frame_ok = x_frame['status'] == 'OK'
        csp_frame_ok = False
        if csp['value'] != 'N/A' and 'frame-ancestors' in csp['value']:
            csp_frame_ok = True
        
        if not x_frame_ok and not csp_frame_ok:
            cj_vulnerable = True
            if x_frame['status'] == 'MISSING': cj_reasons.append("X-Frame-Options is missing")
            elif x_frame['status'] == 'MISCONFIGURED': cj_reasons.append("X-Frame-Options is weak")
            if not csp_frame_ok: cj_reasons.append("CSP frame-ancestors directive missing")
        
        clickjacking = {
            'is_vulnerable': cj_vulnerable,
            'reasons': cj_reasons
        }

        # 3. Info Disclosure
        disclosure = {}
        for h in INFO_HEADERS:
            val = response.headers.get(h)
            if not val: 
                for rh in response.headers:
                    if rh.lower() == h.lower(): val = response.headers[rh]
            if val:
                disclosure[h] = val

        # 4. Fingerprinting
        tech_stack = set()
        header_dump = str(response.headers)
        for tech, sig in SIGS.items():
            if 'headers' in sig:
                for p in sig['headers']:
                    if re.search(p, header_dump, re.IGNORECASE): tech_stack.add(tech)
        for cookie in response.cookies:
            for tech, sig in SIGS.items():
                if 'cookies' in sig:
                    for p in sig['cookies']:
                        if p in cookie.name: tech_stack.add(tech)
        body_content = response.text
        for tech, sig in SIGS.items():
            if 'body' in sig:
                for p in sig['body']:
                    if p in body_content: tech_stack.add(tech)

        return {
            'url': url,
            'status_code': response.status_code,
            'headers_analysis': results,
            'clickjacking': clickjacking,
            'disclosure': disclosure,
            'tech_stack': list(tech_stack),
            'raw_request': construct_raw_request(response.request),
            'raw_response': construct_raw_response(response)
        }

    except requests.exceptions.RequestException as e:
        print(f"❌ Error connecting to {url}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

# --- Output Generators ---

def print_terminal(data):
    print(f"\n🔎  Analysis for: \033[1m{data['url']}\033[0m")
    print(f"📡  Status Code: {data['status_code']}\n")
    
    # Clickjacking Alert
    if data['clickjacking']['is_vulnerable']:
        print(f"\033[91m🚨  CLICKJACKING VULNERABILITY DETECTED!\033[0m")
        for r in data['clickjacking']['reasons']:
            print(f"    └── {r}")
        print("")

    print("🛡️   SECURITY HEADERS ANALYSIS")
    print("-" * 60)
    for header, res in data['headers_analysis'].items():
        if res['status'] == 'OK':
            icon = "✅"
            color = "\033[92m" 
        elif res['status'] == 'MISSING':
            icon = "❌"
            color = "\033[91m" 
        else:
            icon = "⚠️ "
            color = "\033[93m" 
        
        print(f"{icon}  {color}{header:<25}\033[0m : {res['status']}")
        
        print(f"    ℹ️  {res['desc']}")
        print(f"    💡 Best Practice: {res['best']}")
        
        if res['status'] != 'OK':
            print(f"    ⚠️  Issue: {res['msg']}")
            if res['status'] == 'MISCONFIGURED':
                print(f"    🚫 Vulnerable Config: {res['value']}")
        
        print("") 

    print("\n🕵️   INFORMATION DISCLOSURE")
    print("-" * 60)
    if data['disclosure']:
        for k, v in data['disclosure'].items():
            print(f"⚠️   {k}: {v}")
    else:
        print("✅  No common server version headers leaked.")

    print("\n🧬  TECHNOLOGY FINGERPRINT")
    print("-" * 60)
    if data['tech_stack']:
        print(f"🛠️   Detected: {', '.join(data['tech_stack'])}")
    else:
        print("❓  No specific technologies detected.")
    
    print("\n" + "-" * 60)
    print("👨‍💻 Developed by h4rithd.com (Harith Dilshan)")
    print("-" * 60 + "\n")

def generate_html(data, filename):
    if not filename.endswith('.html'):
        filename += '.html'

    rows = ""
    for header, res in data['headers_analysis'].items():
        status_class = "bg-green-100 text-green-800"
        status_icon = "✅ OK"
        if res['status'] == 'MISSING':
            status_class = "bg-red-100 text-red-800"
            status_icon = "❌ Missing"
        elif res['status'] == 'MISCONFIGURED':
            status_class = "bg-yellow-100 text-yellow-800"
            status_icon = "⚠️ Weak"

        rows += f"""
        <tr class="hover:bg-gray-50 border-b border-gray-100">
            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{header}</td>
            <td class="px-6 py-4 whitespace-nowrap"><span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full {status_class}">{status_icon}</span></td>
            <td class="px-6 py-4 text-sm text-gray-500 font-mono break-all">{res['value'][:60]}{'...' if len(res['value']) > 60 else ''}</td>
            <td class="px-6 py-4 text-sm text-gray-500">{res['rec']}</td>
        </tr>
        """
    
    # Generate Knowledge Base Cards for HTML
    kb_cards = ""
    for header, res in data['headers_analysis'].items():
        kb_cards += f"""
        <div class="bg-gray-50 rounded-lg p-4 border border-gray-200 shadow-sm">
            <h4 class="font-bold text-gray-800 mb-2">{header}</h4>
            <p class="text-sm text-gray-600 mb-3">{res['desc']}</p>
            <div class="text-xs font-mono bg-indigo-50 text-indigo-800 p-2 rounded border border-indigo-100">
                <span class="font-bold">Best Practice:</span> {res['best']}
            </div>
        </div>
        """

    # Clickjacking Logic for HTML
    cj_status = data['clickjacking']['is_vulnerable']
    cj_header_class = "bg-red-600" if cj_status else "bg-green-600"
    cj_title = "VULNERABLE to Clickjacking" if cj_status else "Secure against Clickjacking"
    cj_msg = "The following protection headers are missing:" if cj_status else "Your site correctly refuses to be framed."
    cj_reasons_html = ""
    if cj_status:
        for r in data['clickjacking']['reasons']:
            cj_reasons_html += f"<li class='text-red-700 font-mono text-sm'>• {r}</li>"
    else:
        cj_reasons_html = "<li class='text-green-700 font-mono text-sm'>• X-Frame-Options or CSP frame-ancestors is active.</li>"

    disclosure_html = ""
    if data['disclosure']:
        for k, v in data['disclosure'].items():
            disclosure_html += f"<div class='flex items-center text-red-600 mb-1'><span class='font-bold mr-2'>{k}:</span> {v}</div>"
    else:
        disclosure_html = "<div class='text-green-600 font-medium'>No server version headers leaked.</div>"

    tech_html = ""
    if data['tech_stack']:
        for t in data['tech_stack']:
            tech_html += f"<span class='inline-block bg-blue-600 text-white text-sm px-3 py-1 rounded-full mr-2 mb-2 shadow-sm'>{t}</span>"
    else:
        tech_html = "<span class='text-gray-500 italic'>No specific stack signatures found.</span>"

    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SecHead: {data['url']}</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            body {{ font-family: 'Inter', sans-serif; background-color: #f3f4f6; }}
            pre {{ white-space: pre-wrap; word-wrap: break-word; }}
            .iframe-container {{ position: relative; width: 100%; height: 500px; border: 2px dashed #cbd5e1; background: #fff; }}
        </style>
    </head>
    <body class="p-8">
        <div class="max-w-6xl mx-auto space-y-8">
            
            <div class="bg-white shadow-md rounded-lg overflow-hidden border-l-4 border-indigo-600">
                <div class="p-6">
                    <h1 class="text-3xl font-bold text-gray-800">🛡️ SecHead Report</h1>
                    <div class="mt-2 text-gray-600 flex justify-between">
                        <p>Target: <a href="{data['url']}" class="text-indigo-600 font-mono">{data['url']}</a></p>
                        <p class="text-sm">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                </div>
            </div>

            <div class="bg-white shadow-md rounded-lg overflow-hidden">
                <div class="{cj_header_class} px-6 py-4 flex justify-between items-center">
                    <h3 class="text-lg font-bold text-white">🖱️ Clickjacking Test</h3>
                    <span class="bg-white text-gray-800 px-3 py-1 rounded-full text-xs font-bold">{cj_title.upper()}</span>
                </div>
                <div class="p-6">
                    <p class="text-gray-700 mb-2 font-semibold">{cj_msg}</p>
                    <ul class="list-none mb-4 pl-2 border-l-2 border-gray-300">
                        {cj_reasons_html}
                    </ul>
                    <p class="text-xs text-gray-500 mb-2 uppercase tracking-wide">Live Iframe Check:</p>
                    <div class="iframe-container rounded-lg overflow-hidden">
                        <div class="absolute inset-0 flex items-center justify-center pointer-events-none z-0">
                            <span class="text-gray-400 text-sm">If website loads here, it is Vulnerable. <br> (If blank/error, it is Protected)</span>
                        </div>
                        <iframe src="{data['url']}" class="w-full h-full relative z-10" style="border:none;"></iframe>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="bg-white shadow-md rounded-lg p-6 border-t-4 border-blue-500">
                    <h3 class="text-lg font-bold text-gray-800 mb-4">🧬 Technology Stack</h3>
                    <div class="flex flex-wrap">{tech_html}</div>
                </div>
                <div class="bg-white shadow-md rounded-lg p-6 border-t-4 border-red-500">
                    <h3 class="text-lg font-bold text-gray-800 mb-4">🕵️ Info Disclosure</h3>
                    {disclosure_html}
                </div>
            </div>

            <div class="bg-white shadow-md rounded-lg overflow-hidden">
                <div class="bg-gray-800 px-6 py-4">
                    <h3 class="text-lg font-bold text-white">Security Headers Details</h3>
                </div>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Header</th>
                                <th class="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Status</th>
                                <th class="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Current Value</th>
                                <th class="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Recommendation</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white">{rows}</tbody>
                    </table>
                </div>
            </div>

            <div class="bg-white shadow-md rounded-lg overflow-hidden">
                <div class="bg-indigo-700 px-6 py-4">
                    <h3 class="text-lg font-bold text-white">📚 Header Knowledge Base</h3>
                </div>
                <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-4">
                    {kb_cards}
                </div>
            </div>

            <div class="bg-white shadow-md rounded-lg overflow-hidden">
                <div class="bg-gray-800 px-6 py-4 border-b border-gray-700">
                    <h3 class="text-lg font-bold text-white">📝 Raw Traffic</h3>
                </div>
                <div class="grid grid-cols-1 lg:grid-cols-2">
                    <div class="p-0 border-r border-gray-700">
                        <div class="bg-gray-200 px-4 py-2 text-xs font-bold text-gray-600 uppercase">Request</div>
                        <div class="p-4 bg-gray-900 overflow-auto h-96">
                            <pre class="text-green-400 font-mono text-xs">{data['raw_request']}</pre>
                        </div>
                    </div>
                    <div class="p-0">
                        <div class="bg-gray-200 px-4 py-2 text-xs font-bold text-gray-600 uppercase">Response</div>
                        <div class="p-4 bg-gray-900 overflow-auto h-96">
                            <pre class="text-blue-400 font-mono text-xs">{data['raw_response']}</pre>
                        </div>
                    </div>
                </div>
            </div>

            <div class="text-center text-gray-500 text-xs py-4 border-t border-gray-200 mt-6">
                Developed by <a href="https://h4rithd.com" target="_blank" class="text-indigo-600 hover:underline font-bold">h4rithd.com</a> aka Harith Dilshan
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_template)
    print(f"\n💾  HTML Report saved to: \033[1m{filename}\033[0m")

# --- Main Execution ---

def main():
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description="SecHead - Security Header Analyzer")
    parser.add_argument('-u', '--url', required=True, help="Target URL (e.g. https://h4rithd.com)")
    parser.add_argument('-o', '--output', help="Output file for HTML report (e.g. report)")
    args = parser.parse_args()
    
    url = args.url
    if not url.startswith('http'): url = 'https://' + url

    print(f"🚀  Starting analysis for {url}...")
    data = analyze_target(url)
    print_terminal(data)
    
    if args.output:
        generate_html(data, args.output)

if __name__ == "__main__":
    main()
