# VulnWhisper - Security Blog Post Analyzer

VulnWhisper is an AI-powered security blog post analyzer that helps security professionals quickly digest technical content by providing concise summaries and extracting key technical information.

## Features

- **Smart Summarization**: Uses AI to create focused summaries of security blog posts while preserving technical details
- **Technical Detail Extraction**: Automatically identifies and categorizes:
  - Vulnerabilities and CVEs
  - Malware Behavior
  - System Artifacts
  - Network Indicators
  - Attack Techniques
  - Detection Methods
- **IOC Extraction**: Automatically extracts:
  - IP Addresses
  - File Hashes (MD5, SHA1, SHA256)
  - Malware Identifiers
- **Clean Web Interface**: Simple and intuitive web interface for analyzing blog posts
- **Progress Tracking**: Visual feedback during the analysis process
- **Rate Limiting**: Built-in protection against abuse (optional, requires Redis)
- **Caching**: Caches results for faster repeated access (optional, requires Redis)

## Technical Stack

- Python 3.12+
- FastAPI
- Hugging Face Transformers (BART-CNN model)
- BeautifulSoup4
- Redis (optional, for rate limiting and caching)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/vulnwhisper.git
cd vulnwhisper
```

2. Create a virtual environment and activate it:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the server:
```bash
python -m uvicorn src.main:app --reload
```

2. Open your browser and navigate to:
```
http://127.0.0.1:8000
```

3. Enter the URL of a security blog post and click "Analyze"

## Example Output

The tool provides structured output including:

```
Threat: [Identified Threat Name]

Overview:
[Concise summary of the security incident or vulnerability]

Technical Analysis:

Vulnerability Analysis:
• [Detailed vulnerability information]
• [CVE references]

Malware Behavior:
• [Detailed malware actions and capabilities]
• [Command and control information]

System Artifacts:
• [File paths]
• [Registry keys]
• [Process information]

Network Indicators:
• [IP addresses]
• [Domains]
• [Network protocols used]

Attack Techniques:
• [MITRE ATT&CK references]
• [Attack methodologies]

Detection Methods:
• [YARA rules]
• [Detection signatures]
• [Log sources]

Indicators of Compromise (IOCs):
• [List of extracted IOCs]
```

## Optional Features

### Redis Integration

To enable rate limiting and caching:

1. Install Redis on your system
2. Start the Redis server
3. The application will automatically detect and use Redis if available

## Development

### Running Tests

```bash
python -m pytest tests/
```

### Project Structure

```
vulnwhisper/
├── src/
│   ├── __init__.py
│   └── main.py          # Main application logic
├── tests/
│   └── test_main.py     # Test cases
├── requirements.txt     # Project dependencies
└── README.md           # This file
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) for the web framework
- [Hugging Face Transformers](https://huggingface.co/transformers/) for the AI summarization
- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) for web scraping