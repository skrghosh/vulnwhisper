from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl, validator
import requests
from bs4 import BeautifulSoup
from transformers import pipeline
import re
import logging
from datetime import datetime, timedelta
from typing import Optional, List
import hashlib
from functools import lru_cache
import redis
import time
from urllib.parse import urlparse

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Redis for rate limiting and caching
redis_client = None
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_client.ping()
    logger.info("Redis connection established successfully")
except Exception as e:
    logger.info(f"Redis not available (this is optional): {str(e)}")
    redis_client = None

app = FastAPI(
    title="Security Blog Summarizer",
    description="API for summarizing security blog posts and extracting IOCs",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# HTML template for the interface
HTML_CONTENT = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Blog Summarizer</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .container { margin-top: 20px; }
        input[type="url"] { width: 100%; padding: 8px; margin: 10px 0; }
        button { padding: 10px 20px; background: #4CAF50; color: white; border: none; cursor: pointer; }
        button:hover { background: #45a049; }
        button:disabled { background: #cccccc; cursor: not-allowed; }
        #result { margin-top: 20px; }
        .ioc-list { margin-top: 10px; }
        .error { color: red; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-top: 10px; }
        .progress { margin-top: 20px; }
        .progress-step { padding: 8px; margin: 5px 0; border-radius: 3px; }
        .progress-step.active { background: #e8f5e9; border-left: 4px solid #4CAF50; }
        .progress-step.done { background: #f5f5f5; border-left: 4px solid #999; color: #666; }
    </style>
</head>
<body>
    <h1>Security Blog Summarizer</h1>
    <div class="container">
        <label for="url">Enter Security Blog URL:</label>
        <input type="url" id="url" placeholder="https://example.com/security-blog-post" required>
        <button onclick="summarizeBlog()" id="analyzeBtn">Analyze</button>
        
        <div id="progress" class="progress" style="display: none;">
            <div id="step1" class="progress-step">⏳ Fetching blog content...</div>
            <div id="step2" class="progress-step">Extracting IOCs...</div>
            <div id="step3" class="progress-step">Generating detailed summary...</div>
        </div>
        
        <div id="result"></div>
    </div>
    <script>
        function updateProgress(step) {
            const steps = {
                1: 'step1',
                2: 'step2',
                3: 'step3'
            };
            
            // Mark previous steps as done
            for (let i = 1; i < step; i++) {
                document.getElementById(steps[i]).className = 'progress-step done';
                document.getElementById(steps[i]).textContent = 
                    document.getElementById(steps[i]).textContent.replace('⏳', '✓');
            }
            
            // Mark current step as active
            if (step <= 3) {
                document.getElementById(steps[step]).className = 'progress-step active';
            }
        }

        async function summarizeBlog() {
            const url = document.getElementById('url').value;
            const resultDiv = document.getElementById('result');
            const analyzeBtn = document.getElementById('analyzeBtn');
            const progressDiv = document.getElementById('progress');
            
            // Reset and show progress
            resultDiv.innerHTML = '';
            progressDiv.style.display = 'block';
            analyzeBtn.disabled = true;
            
            // Reset progress steps
            document.querySelectorAll('.progress-step').forEach(step => {
                step.className = 'progress-step';
                if (step.textContent.includes('✓')) {
                    step.textContent = step.textContent.replace('✓', '⏳');
                }
            });
            
            try {
                updateProgress(1);
                const response = await fetch('/summarize', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    updateProgress(3);
                    let html = '<h2>Analysis Results</h2>';
                    html += '<h3>Summary</h3>';
                    html += `<div class="summary">${data.summary}</div>`;
                    
                    if (data.iocs && data.iocs.length > 0) {
                        html += '<h3>Indicators of Compromise (IOCs)</h3>';
                        html += '<div class="ioc-list"><ul>';
                        data.iocs.forEach(ioc => {
                            html += `<li>${ioc}</li>`;
                        });
                        html += '</ul></div>';
                    } else {
                        html += '<p>No IOCs found in the article.</p>';
                    }
                    
                    // Small delay to show the final progress state
                    setTimeout(() => {
                        resultDiv.innerHTML = html;
                        analyzeBtn.disabled = false;
                        // Hide progress after showing results
                        setTimeout(() => {
                            progressDiv.style.display = 'none';
                        }, 1000);
                    }, 500);
                } else {
                    resultDiv.innerHTML = `<div class="error">Error: ${data.detail}</div>`;
                    analyzeBtn.disabled = false;
                    progressDiv.style.display = 'none';
                }
            } catch (error) {
                resultDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
                analyzeBtn.disabled = false;
                progressDiv.style.display = 'none';
            }
        }
    </script>
</body>
</html>
"""

class BlogURL(BaseModel):
    url: HttpUrl

    @validator('url')
    def validate_url(cls, v):
        # Basic URL validation - just ensure it's a valid HTTP(S) URL
        try:
            parsed_url = urlparse(str(v))
            if parsed_url.scheme not in ('http', 'https'):
                raise ValueError("URL must use HTTP or HTTPS protocol")
            return v
        except Exception as e:
            raise ValueError(f"Invalid URL format: {str(e)}")

class Summary(BaseModel):
    summary: str
    iocs: List[str]
    threat_name: str = ""
    processed_at: datetime = None
    source_url: str = None

def clean_text(text: str) -> str:
    """Clean and normalize text content."""
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    
    # Remove common boilerplate patterns
    patterns_to_remove = [
        r'For confidential support.*?(?=\s*\w+)',  # Support numbers and info
        r'(?i)call.*?(\+\d{1,}|\d{3,}).*?(?=\s*\w+)',  # Phone numbers
        r'©.*?(?=\s*\w+)',  # Copyright notices
        r'(?i)privacy policy|terms of service|cookie policy',  # Legal links
        r'(?i)subscribe to our newsletter',  # Newsletter prompts
        r'(?i)share this article',  # Social sharing
        r'(?i)related articles',  # Related content section
        r'(?i)download.*?free trial',  # Trial/download prompts
        r'(?i)advertisement',  # Advertisement labels
        r'(?i)comments?(\s|$)',
        r'(?i)posted by.*?(\n|$)',
        r'(?i)author:.*?(\n|$)'
    ]
    
    for pattern in patterns_to_remove:
        text = re.sub(pattern, '', text)
    
    return text.strip()

def extract_iocs(text: str) -> list[str]:
    """Extract Indicators of Compromise (IOCs) from text - focused on hashes and IPs."""
    iocs = []
    
    # IP address pattern (IPv4) with strict validation
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ip_matches = re.findall(ip_pattern, text)
    for ip in ip_matches:
        iocs.append(f"IP: {ip}")
    
    # Hash patterns with validation
    hash_patterns = {
        'MD5': r'\b[a-fA-F0-9]{32}\b',
        'SHA1': r'\b[a-fA-F0-9]{40}\b',
        'SHA256': r'\b[a-fA-F0-9]{64}\b'
    }
    
    for hash_type, pattern in hash_patterns.items():
        matches = re.findall(pattern, text)
        for match in matches:
            # Validate that it's an actual hash (must contain both letters and numbers)
            if any(c.isdigit() for c in match) and any(c.isalpha() for c in match):
                iocs.append(f"{hash_type}: {match}")
    
    # Only include malware identifiers if they match a very specific pattern
    # This pattern looks for something like Malware.AI.1323738514
    malware_pattern = r'\b(?:Malware|Trojan)\.AI\.\d+\b'
    malware_matches = re.findall(malware_pattern, text)
    iocs.extend(malware_matches)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_iocs = []
    for ioc in iocs:
        if ioc.lower() not in seen:
            seen.add(ioc.lower())
            unique_iocs.append(ioc)
    
    return unique_iocs

def extract_threat_name(text: str) -> str:
    """Extract malware/threat name from text."""
    threat_patterns = [
        r'(?i)detected as[:\s]+([A-Za-z0-9._-]+(?:\.[A-Za-z0-9_-]+)+)',
        r'(?i)identified as[:\s]+([A-Za-z0-9._-]+(?:\.[A-Za-z0-9_-]+)+)',
        r'(?i)malware[:\s]+([A-Za-z0-9._-]+(?:\.[A-Za-z0-9_-]+)+)',
        r'(?i)trojan[:\s]+([A-Za-z0-9._-]+(?:\.[A-Za-z0-9_-]+)+)'
    ]
    
    for pattern in threat_patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return ""

def extract_main_content(soup: BeautifulSoup) -> str:
    """Extract the main article content while avoiding boilerplate."""
    # Remove unwanted elements
    for element in soup.find_all(['script', 'style', 'nav', 'footer', 'header', 'aside', 'form']):
        element.decompose()
    
    # Try to find the main article content
    main_content = None
    
    # Common article container selectors
    article_selectors = [
        'article',
        '[role="main"]',
        '.post-content',
        '.article-content',
        '.entry-content',
        '.blog-post',
        'main',
        '#main-content'
    ]
    
    # Try each selector until we find content
    for selector in article_selectors:
        content = soup.select_one(selector)
        if content and len(content.get_text(strip=True)) > 200:  # Minimum content length
            main_content = content
            break
    
    # If no main content found, try to find the largest text block
    if not main_content:
        text_blocks = []
        for p in soup.find_all('p'):
            text = p.get_text(strip=True)
            if len(text) > 50:  # Ignore very short paragraphs
                text_blocks.append(text)
        
        if text_blocks:
            return ' '.join(text_blocks)
    
    # Clean and return the content
    if main_content:
        return clean_text(main_content.get_text(strip=True))
    
    # Fallback to cleaned full page content
    return clean_text(soup.get_text(strip=True))

def extract_technical_details(text: str) -> dict:
    """Extract detailed technical information organized by categories."""
    technical_info = {
        'vulnerabilities': [],
        'malware_behavior': [],
        'system_artifacts': [],
        'network_indicators': [],
        'attack_techniques': [],
        'detection_methods': []
    }
    
    # Vulnerability patterns - more precise
    vuln_patterns = [
        r'(?i)CVE-\d{4}-\d{4,7}',
        r'(?i)(?:critical|high|medium|low)\s+severity\s+vulnerability',
        r'(?i)(?:zero-day|0-day)\s+vulnerability',
        r'(?i)CVSS\s*v\d\s*score:\s*\d+\.\d+'
    ]
    
    # Malware behavior patterns - focused on specific actions
    behavior_patterns = [
        r'(?i)(?:malware|sample)\s+(?:drops?|downloads?|executes?)\s+(?:file|payload)',
        r'(?i)(?:establishes?|initiates?)\s+(?:C2|command\s*and\s*control)',
        r'(?i)(?:steals?|exfiltrates?)\s+(?:data|credentials|files)',
        r'(?i)persistence\s+mechanism:\s*[^\.]+',
        r'(?i)privilege\s+escalation\s+(?:through|via|using)'
    ]
    
    # System artifacts patterns - specific to technical indicators
    artifact_patterns = [
        r'(?i)file\s*path:\s*(?:[A-Za-z]:\\|\/)[^\s,]+',
        r'(?i)registry\s*key:\s*HKEY_[^\s,]+',
        r'(?i)process\s*name:\s*[^\s,]+\.(?:exe|dll)',
        r'(?i)(?:MD5|SHA1|SHA256):\s*[a-fA-F0-9]+',
        r'(?i)scheduled\s+task:\s*[^\s,]+'
    ]
    
    # Network indicator patterns - specific to networking
    network_patterns = [
        r'(?i)C2\s+(?:server|domain):\s*[^\s,]+',
        r'(?i)(?:IP|host):\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        r'(?i)port:\s*\d+(?:\/(?:tcp|udp))?',
        r'(?i)(?:http|https|ftp|smb|rdp)\s+traffic\s+(?:to|from)',
        r'(?i)DNS\s+query:\s*[^\s,]+'
    ]
    
    # Attack technique patterns - specific to MITRE and known techniques
    technique_patterns = [
        r'(?i)MITRE\s+ATT&CK:\s*T\d{4}(?:\.\d{3})?',
        r'(?i)technique\s*ID:\s*T\d{4}(?:\.\d{3})?',
        r'(?i)lateral\s+movement\s+(?:using|via|through)',
        r'(?i)memory\s+injection\s+(?:using|via|method)',
        r'(?i)living\s+off\s+the\s+land\s+(?:using|via|with)'
    ]
    
    # Detection methods patterns - specific to security tools and methods
    detection_patterns = [
        r'(?i)YARA\s+rule:\s*[^\n]+',
        r'(?i)Sigma\s+rule:\s*[^\n]+',
        r'(?i)detection\s+method:\s*[^\n]+',
        r'(?i)IOC\s+type:\s*[^\n]+',
        r'(?i)(?:Sysmon|EDR)\s+event\s+ID:\s*\d+'
    ]
    
    pattern_categories = [
        ('vulnerabilities', vuln_patterns),
        ('malware_behavior', behavior_patterns),
        ('system_artifacts', artifact_patterns),
        ('network_indicators', network_patterns),
        ('attack_techniques', technique_patterns),
        ('detection_methods', detection_patterns)
    ]
    
    # Extract details with context
    for category, patterns in pattern_categories:
        for pattern in patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                # Get context around the match
                start = max(0, match.start() - 100)  # Reduced context
                end = min(len(text), match.end() + 100)  # Reduced context
                context = text[start:end].strip()
                
                # Clean up the context
                context = re.sub(r'\s+', ' ', context)
                context = context.replace('\n', ' ').strip()
                
                # Only add if it's not a subset of existing entries
                if not any(context in existing or existing in context 
                          for existing in technical_info[category]):
                    technical_info[category].append(context)
    
    return technical_info

def format_technical_details(details: dict) -> str:
    """Format technical details into a structured summary with clear section separation."""
    sections = []
    
    section_titles = {
        'vulnerabilities': 'Vulnerability Analysis',
        'malware_behavior': 'Malware Behavior',
        'system_artifacts': 'System Artifacts',
        'network_indicators': 'Network Indicators',
        'attack_techniques': 'Attack Techniques',
        'detection_methods': 'Detection Methods'
    }
    
    for category, items in details.items():
        if items:
            # Add visual separation for each section with 10 asterisks
            section = f"\n{'*'*10}\n{section_titles[category]}\n{'*'*10}\n\n"
            for item in items:
                # Format each item with bullet points and ensure line breaks
                section += f"• {item.strip()}\n\n"
            sections.append(section)
    
    return '\n'.join(sections) if sections else ""

def extract_key_points(text: str) -> str:
    """Extract key security-relevant points from the text."""
    security_keywords = [
        # Threat categories
        r'malware', r'ransomware', r'trojan', r'backdoor', r'rootkit', r'keylogger',
        r'spyware', r'adware', r'worm', r'virus', r'botnet', r'cryptominer',
        
        # Attack vectors
        r'exploit', r'vulnerability', r'zero-day', r'0-day', r'rce', r'buffer overflow',
        r'sql injection', r'xss', r'csrf', r'phishing', r'social engineering',
        
        # Technical indicators
        r'payload', r'shellcode', r'command\s*(?:and|&)\s*control', r'c2',
        r'persistence', r'lateral movement', r'privilege escalation',
        
        # Attack phases
        r'reconnaissance', r'initial access', r'execution', r'persistence',
        r'defense evasion', r'credential access', r'discovery', r'collection',
        r'exfiltration', r'impact',
        
        # Technical components
        r'process injection', r'dll', r'registry', r'powershell', r'wmi',
        r'task scheduler', r'service', r'driver', r'kernel', r'memory',
        
        # Network-related
        r'dns', r'http', r'https', r'ftp', r'smb', r'rdp', r'ssh',
        r'certificate', r'encryption', r'protocol', r'packet',
        
        # Detection & Analysis
        r'ioc', r'indicator', r'signature', r'yara', r'snort', r'wireshark',
        r'packet capture', r'memory dump', r'log analysis'
    ]
    
    sentences = re.split(r'(?<=[.!?])\s+', text)
    key_sentences = []
    
    for sentence in sentences:
        if any(re.search(rf'\b{keyword}\b', sentence.lower()) for keyword in security_keywords):
            key_sentences.append(sentence)
    
    return ' '.join(key_sentences) if key_sentences else text

def fetch_blog_content(url: str) -> str:
    """Fetch and extract text content from the blog URL."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, timeout=10, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        return extract_main_content(soup)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error fetching content: {str(e)}")

# Rate limiting
async def check_rate_limit(request: Request):
    # Skip rate limiting if Redis is not available
    if not redis_client:
        return True
    
    try:
        client_ip = request.client.host
        key = f"rate_limit:{client_ip}"
        
        # Allow 10 requests per minute
        pipe = redis_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, 60)
        result = pipe.execute()
        count = result[0]
        
        if count > 10:
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please try again in a minute."
            )
        return True
    except redis.RedisError:
        # If Redis fails, don't block the request
        logger.warning("Redis error during rate limiting, skipping check")
        return True

# Caching
@lru_cache(maxsize=100)
def get_cached_summary(url: str) -> Optional[Summary]:
    if not redis_client:
        return None
        
    cache_key = f"summary:{hashlib.md5(url.encode()).hexdigest()}"
    cached = redis_client.get(cache_key)
    if cached:
        return Summary.parse_raw(cached)
    return None

def cache_summary(url: str, summary: Summary, expire_time: int = 3600):
    if not redis_client:
        return
        
    cache_key = f"summary:{hashlib.md5(url.encode()).hexdigest()}"
    redis_client.setex(cache_key, expire_time, summary.json())

def clean_summary(text: str) -> str:
    """Clean up summary to ensure complete sentences."""
    if not text:
        return text
        
    # Function to check if a sentence is complete
    def is_complete_sentence(sentence: str) -> bool:
        # Remove extra spaces and check if empty
        sentence = sentence.strip()
        if not sentence:
            return False
            
        # Must have at least one word character
        if not any(c.isalpha() for c in sentence):
            return False
            
        # Check for proper ending
        return bool(re.search(r'[.!?]$', sentence))
    
    # Split into sentences more robustly
    # This handles multiple types of sentence endings and preserves them
    sentences = []
    current = []
    
    # Split on sentence boundaries but keep the delimiters
    parts = re.split(r'([.!?]+(?:\s+|$))', text)
    
    for i in range(0, len(parts)-1, 2):
        if i+1 < len(parts):
            sentence = parts[i] + parts[i+1]
            if sentence.strip():
                sentences.append(sentence.strip())
    
    # Handle any remaining text
    if len(parts) % 2 == 1 and parts[-1].strip():
        last_part = parts[-1].strip()
        # Only include the last part if it looks like a complete sentence
        if is_complete_sentence(last_part):
            sentences.append(last_part)
    
    # Filter out incomplete sentences
    complete_sentences = [s for s in sentences if is_complete_sentence(s)]
    
    # If we have no complete sentences, try to complete the last one
    if not complete_sentences and sentences:
        last_sentence = sentences[-1].strip()
        if last_sentence and any(c.isalpha() for c in last_sentence):
            last_sentence = last_sentence + '.'
            complete_sentences.append(last_sentence)
    
    return ' '.join(complete_sentences) if complete_sentences else text

def chunk_text(text: str, max_length: int = 1024) -> list[str]:
    """Split text into chunks while preserving sentence boundaries."""
    if len(text) <= max_length:
        return [text]
        
    chunks = []
    current_chunk = []
    current_length = 0
    
    # Split on sentence boundaries but keep the delimiters
    sentences = []
    parts = re.split(r'([.!?]+(?:\s+|$))', text)
    
    for i in range(0, len(parts)-1, 2):
        if i+1 < len(parts):
            sentences.append(parts[i] + parts[i+1])
    
    # Handle any remaining text
    if len(parts) % 2 == 1 and parts[-1].strip():
        sentences.append(parts[-1])
    
    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence:
            continue
            
        # If adding this sentence would exceed the limit
        if current_length + len(sentence) > max_length and current_chunk:
            # Save current chunk and start a new one
            chunks.append(' '.join(current_chunk))
            current_chunk = []
            current_length = 0
        
        current_chunk.append(sentence)
        current_length += len(sentence) + 1  # +1 for space
    
    # Add any remaining chunk
    if current_chunk:
        chunks.append(' '.join(current_chunk))
    
    return chunks

@app.post("/summarize", response_model=Summary, dependencies=[Depends(check_rate_limit)])
async def summarize_blog(blog_url: BlogURL):
    """Fetch blog content, summarize it, and extract IOCs."""
    url = str(blog_url.url)
    logger.info(f"Processing URL: {url}")
    
    try:
        # Check cache first
        cached = get_cached_summary(url)
        if cached:
            logger.info(f"Cache hit for URL: {url}")
            return cached
        
        # Initialize the summarization pipeline
        summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
        
        # Fetch and clean content
        content = fetch_blog_content(url)
        logger.debug(f"Fetched content length: {len(content)}")
        
        # Extract key security-related content
        security_content = extract_key_points(content)
        
        # Extract detailed technical information
        technical_info = extract_technical_details(content)
        formatted_technical_details = format_technical_details(technical_info)
        
        # Extract IOCs and threat name
        iocs = extract_iocs(content)
        threat_name = extract_threat_name(content)
        
        # Generate summary using chunks
        chunks = chunk_text(security_content, max_length=1024)
        summaries = []
        
        for chunk in chunks[:2]:  # Process first two chunks
            if len(chunk.strip()) > 100:
                summary = summarizer(chunk,
                                  max_length=300,
                                  min_length=100,
                                  do_sample=False,
                                  num_beams=4,
                                  length_penalty=2.0,
                                  early_stopping=True)
                clean_text = clean_summary(summary[0]['summary_text'])
                if clean_text:
                    summaries.append(clean_text)
        
        main_summary = ' '.join(summaries)
        
        # Generate technical summary if available
        if technical_content := technical_info.get('malware_behavior', []):
            tech_text = ' '.join(technical_content)
            if len(tech_text) > 100:
                tech_chunks = chunk_text(tech_text, max_length=1024)
                tech_summaries = []
                
                for chunk in tech_chunks[:1]:  # Process first chunk of technical details
                    summary = summarizer(chunk,
                                      max_length=200,
                                      min_length=50,
                                      do_sample=False,
                                      num_beams=4,
                                      length_penalty=1.5)
                    clean_text = clean_summary(summary[0]['summary_text'])
                    if clean_text:
                        tech_summaries.append(clean_text)
                
                if tech_summaries:
                    tech_details = ' '.join(tech_summaries)
                    if tech_details and tech_details not in main_summary:
                        main_summary = f"{main_summary}\n\n{tech_details}"
        
        # Format the final summary with clear section separation and proper line breaks
        final_summary = (
            f"{'*'*10}\n"
            f"OVERVIEW\n"
            f"{'*'*10}\n\n"
            f"{main_summary}\n"
        )
        
        if threat_name:
            final_summary = (
                f"{'*'*10}\n"
                f"THREAT\n"
                f"{'*'*10}\n\n"
                f"{threat_name}\n\n"
                f"{final_summary}"
            )
        
        if formatted_technical_details:
            final_summary += (
                f"\n{'*'*10}\n"
                f"TECHNICAL ANALYSIS\n"
                f"{'*'*10}\n"
                f"{formatted_technical_details}"
            )

        # Create summary object
        result = Summary(
            summary=final_summary,
            iocs=iocs,
            threat_name=threat_name,
            processed_at=datetime.utcnow(),
            source_url=url
        )
        
        # Cache the result
        cache_summary(url, result)
        
        logger.info(f"Successfully processed URL: {url}")
        return result
        
    except Exception as e:
        logger.error(f"Error processing URL {url}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the HTML interface."""
    return HTMLResponse(content=HTML_CONTENT)