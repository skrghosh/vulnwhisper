import pytest
from fastapi.testclient import TestClient
from src.main import app, extract_iocs, extract_threat_name, clean_text, extract_key_points
from datetime import datetime
from unittest.mock import Mock, patch

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "Security Blog Summarizer" in response.text

def test_extract_iocs():
    test_text = """
    Malicious IPs found: 192.168.1.1 and 10.0.0.1
    MD5 hash: d41d8cd98f00b204e9800998ecf8427e
    SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    Detection: Malware.AI.1323738514
    """
    iocs = extract_iocs(test_text)
    
    assert "IP: 192.168.1.1" in iocs
    assert "IP: 10.0.0.1" in iocs
    assert "MD5: d41d8cd98f00b204e9800998ecf8427e" in iocs
    assert "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709" in iocs
    assert "Malware.AI.1323738514" in iocs

def test_extract_threat_name():
    test_cases = [
        ("The sample was detected as Malware.Cryptominer.123", "Malware.Cryptominer.123"),
        ("This trojan was identified as Trojan.Downloader.456", "Trojan.Downloader.456"),
        ("No threat name here", "")
    ]
    
    for test_input, expected in test_cases:
        assert extract_threat_name(test_input) == expected

def test_clean_text():
    test_text = """
    Main article content.
    For confidential support call 123-456-7890
    Subscribe to our newsletter!
    Share this article on social media
    Related articles you might like
    """
    cleaned = clean_text(test_text)
    
    assert "Main article content" in cleaned
    assert "confidential support" not in cleaned
    assert "Subscribe to our newsletter" not in cleaned
    assert "Share this article" not in cleaned
    assert "Related articles" not in cleaned

def test_extract_key_points():
    test_text = """
    First sentence about weather.
    The malware attack compromised several systems.
    Another unrelated sentence about sports.
    A critical vulnerability was discovered.
    """
    key_points = extract_key_points(test_text)
    
    assert "weather" not in key_points
    assert "sports" not in key_points
    assert "malware attack" in key_points
    assert "vulnerability" in key_points

@pytest.mark.asyncio
async def test_invalid_url_format():
    response = client.post("/summarize", json={"url": "not-a-url"})
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_disallowed_domain():
    response = client.post("/summarize", json={"url": "https://example.com/blog"})
    assert response.status_code == 422
    assert "URL must be from a known security blog" in response.json()["detail"]

@pytest.mark.asyncio
async def test_rate_limiting():
    # Mock Redis to test rate limiting
    with patch("src.main.redis_client") as mock_redis:
        mock_redis.get.return_value = "11"  # Simulate rate limit exceeded
        response = client.post("/summarize", 
                             json={"url": "https://www.malwarebytes.com/blog/test"})
        assert response.status_code == 429
        assert "Too many requests" in response.json()["detail"]

@pytest.mark.asyncio
async def test_caching():
    # Mock Redis and cache hit
    cached_summary = {
        "summary": "Cached summary",
        "iocs": ["IP: 192.168.1.1"],
        "threat_name": "Test.Malware.123",
        "processed_at": datetime.utcnow().isoformat(),
        "source_url": "https://test.com"
    }
    
    with patch("src.main.get_cached_summary") as mock_cache:
        mock_cache.return_value = cached_summary
        response = client.post("/summarize", 
                             json={"url": "https://www.malwarebytes.com/blog/test"})
        assert response.status_code == 200
        assert response.json()["summary"] == "Cached summary"