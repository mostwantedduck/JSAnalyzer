# -*- coding: utf-8 -*-
"""
JS Analyzer - Burp Suite Extension
Focused JavaScript analysis with strict endpoint filtering to reduce noise.
"""

from burp import IBurpExtender, IContextMenuFactory, ITab, IHttpListener

from javax.swing import JMenuItem
from java.awt.event import ActionListener
from java.util import ArrayList
from java.io import PrintWriter

import sys
import json
import time
import os
import re
import inspect

# Add extension directory to path
try:
    _frame = inspect.currentframe()
    if _frame and hasattr(_frame, "f_code"):
        ext_dir = os.path.dirname(os.path.abspath(_frame.f_code.co_filename))
    else:
        ext_dir = os.getcwd()
except:
    ext_dir = os.getcwd()

if ext_dir and ext_dir not in sys.path:
    sys.path.insert(0, ext_dir)

from ui.results_panel import ResultsPanel
from pattern_loader import load_patterns

# ==================== LOAD PATTERNS FROM CONFIG ====================
# Patterns are now stored in patterns.json for easier maintenance
_patterns = load_patterns()
ENDPOINT_PATTERNS = _patterns["ENDPOINT_PATTERNS"]
URL_PATTERNS = _patterns["URL_PATTERNS"]
SECRET_PATTERNS = _patterns["SECRET_PATTERNS"]
EMAIL_PATTERN = _patterns["EMAIL_PATTERN"]
FILE_PATTERNS = _patterns["FILE_PATTERNS"]


# ==================== NOISE FILTERS ====================
# Extensive list of patterns to EXCLUDE

# Domains to exclude from URLs (XML namespaces, standards, etc.)
NOISE_DOMAINS = {
    "www.w3.org",
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "purl.org",
    "purl.oclc.org",
    "openoffice.org",
    "docs.oasis-open.org",
    "sheetjs.openxmlformats.org",
    "ns.adobe.com",
    "www.xml.org",
    "example.com",
    "test.com",
    "localhost",
    "127.0.0.1",
    "fusioncharts.com",
    "jspdf.default.namespaceuri",
    "npmjs.org",
    "registry.npmjs.org",
    "github.com/indutny",
    "github.com/crypto-browserify",
    "jqwidgets.com",
    "ag-grid.com",
}

# Path prefixes that indicate module imports (NOT real endpoints)
MODULE_PREFIXES = (
    "./",
    "../",
    ".../",
    "./lib",
    "../lib",
    "./utils",
    "../utils",
    "./node_modules",
    "../node_modules",
    "./src",
    "../src",
    "./dist",
    "../dist",
)

# Patterns that are clearly internal JS/build artifacts
NOISE_PATTERNS = [
    # Module/library imports
    re.compile(r"^\.\.?/"),  # Starts with ./ or ../
    re.compile(r"^[a-z]{2}(-[a-z]{2})?\.js$"),  # Locale files: en.js, en-gb.js
    re.compile(r"^[a-z]{2}(-[a-z]{2})?$"),  # Just locale: en, en-gb
    re.compile(r"-xform$"),  # Excel xform modules
    re.compile(r"^sha\d*$"),  # sha, sha1, sha256
    re.compile(r"^aes$|^des$|^md5$"),  # Crypto modules
    # PDF internal structure
    re.compile(r"^/[A-Z][a-z]+\s"),  # /Type /Font, /Filter /Standard
    re.compile(r"^/[A-Z][a-z]+$"),  # /Parent, /Kids, /Resources
    re.compile(r"^\d+ \d+ R$"),  # PDF object references
    # Excel/XML internal paths
    re.compile(r"^xl/"),  # Excel internal
    re.compile(r"^docProps/"),  # Document properties
    re.compile(r"^_rels/"),  # Relationships
    re.compile(r"^META-INF/"),  # Manifest
    re.compile(r"\.xml$"),  # XML files
    re.compile(r"^worksheets/"),
    re.compile(r"^theme/"),
    # Build/bundler artifacts
    re.compile(r"^webpack"),
    re.compile(r"^zone\.js$"),
    re.compile(r"^readable-stream/"),
    re.compile(r"^process/"),
    re.compile(r"^stream/"),
    re.compile(r"^buffer$"),
    re.compile(r"^events$"),
    re.compile(r"^util$"),
    re.compile(r"^path$"),
    # Generic noise
    re.compile(r"^\+"),  # Starts with +
    re.compile(r"^\$\{"),  # Template literal
    re.compile(r"^#"),  # Fragment only
    re.compile(r"^\?\ref="),
    re.compile(r"^/[a-z]$"),  # Single letter paths
    re.compile(r"^/[A-Z]$"),  # Single letter paths
    re.compile(r"^http://$"),  # Empty http://
    re.compile(r"_ngcontent"),  # Angular internals
]

# Specific strings to exclude
NOISE_STRINGS = {
    "http://",
    "https://",
    "/a",
    "/P",
    "/R",
    "/V",
    "/W",
    "zone.js",
    "bn.js",
    "hash.js",
    "md5.js",
    "sha.js",
    "des.js",
    "asn1.js",
    "declare.js",
    "elliptic.js",
}


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IHttpListener):
    """JS Analyzer with noise-reduced endpoint detection."""

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("JS Analyzer")

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # Results storage
        self.all_findings = []
        self.seen_values = set()
        self.source_map = {}  # Store source body by name

        self._scope_cache_time = 0
        self._scope_cache_value = False

        # Initialize UI
        self.panel = ResultsPanel(callbacks, self)

        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

        self._log("JS Analyzer loaded")

    def _log(self, msg):
        self._stdout.println("[JS Analyzer] " + str(msg))

    def getTabCaption(self):
        return "JS Analyzer"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu = ArrayList()
        try:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                item = JMenuItem("Analyze JS with JS Analyzer")
                item.addActionListener(AnalyzeAction(self, invocation))
                menu.add(item)
        except Exception as e:
            self._log("Menu error: " + str(e))
        return menu

    def _is_scope_active(self):
        """Check if target scope has any active rules."""
        now = time.time()
        if now - self._scope_cache_time < 30:
            return self._scope_cache_value

        is_active = False
        try:
            config_str = self._callbacks.saveConfigAsJson("target.scope")
            if config_str:
                config = json.loads(config_str)
                root = config
                if "target" in root:
                    root = root["target"]
                if "scope" in root:
                    root = root["scope"]

                includes = root.get("include", [])
                for rule in includes:
                    if rule.get("enabled", True):
                        is_active = True
                        break
        except Exception as e:
            self._log("Scope check warning: " + str(e))

        self._scope_cache_time = now
        self._scope_cache_value = is_active
        return is_active

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Automatic scanning of proxy traffic.
        Only scan responses from Proxy (or Spider/Scanner if desired).
        """
        # Only process responses
        if messageIsRequest:
            return

        # Only process Proxy traffic (toolFlag == 4)
        if toolFlag != self._callbacks.TOOL_PROXY:
            return

        # Get URL to check scope and extension
        request_info = self._helpers.analyzeRequest(messageInfo)
        url = request_info.getUrl()
        url_str = str(url)

        self._log("Checking: " + url_str)

        # Check if in scope
        if not self._callbacks.isInScope(url):
            # Not explicitly in scope. Check if scope is active/filled.
            if self._is_scope_active():
                self._log("-> Skipped: Out of active scope")
                return
            else:
                self._log("-> Note: Scope empty, monitoring all traffic.")

        # Check file extension
        path = url.getPath().lower()
        is_js_ext = any(path.endswith(ext) for ext in [".js", ".json", ".map"])

        # Check Content-Type header
        is_js_content = False
        response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
        headers = response_info.getHeaders()

        content_type = "unknown"
        for header in headers:
            if header.lower().startswith("content-type:"):
                content_type = header.split(":", 1)[1].strip()
                value = header.lower()
                if "javascript" in value or "json" in value:
                    is_js_content = True
                    break

        self._log("-> Ext: %s, Type: %s" % (is_js_ext, content_type))

        # Proceed if matches criteria produces
        if is_js_ext or is_js_content:
            self._log("-> MATCH! Analyzing...")
            self.analyze_response(messageInfo)
        else:
            self._log("-> Skipped: Not JS/JSON")

    def analyze_response(self, message_info):
        """Analyze a response."""
        response = message_info.getResponse()
        if not response:
            return

        # Get source URL
        try:
            req_info = self._helpers.analyzeRequest(message_info)
            url = str(req_info.getUrl())

            headers = req_info.getHeaders()
            host_header = None
            origin_header = None
            referer_header = None

            for header in headers:
                if header.lower().startswith("host:"):
                    host_header = header.split(":", 1)[1].strip()
                elif header.lower().startswith("origin:"):
                    origin_header = header.split(":", 1)[1].strip()
                elif header.lower().startswith("referer:"):
                    referer_header = header.split(":", 1)[1].strip()

            if not host_header:
                host_header = "Unknown"

            if not origin_header:
                origin_header = "Unknown"

            if not referer_header:
                referer_header = "Unknown"

            source_name = url.split("/")[-1].split("?")[0] if "/" in url else url
            if len(source_name) > 40:
                source_name = source_name[:40] + "..."
        except:
            url = "Unknown"
            source_name = "Unknown"

        # Get response body
        resp_info = self._helpers.analyzeResponse(response)
        body_offset = resp_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])

        if len(body) < 50:
            return

        self._log("Analyzing: " + source_name)

        new_findings = []

        # Store source body for later viewing
        self.source_map[source_name] = body

        # Register message_info for sending to Repeater
        self.panel.register_message_info(source_name, message_info)

        # 1. Extract endpoints
        try:
            for pattern in ENDPOINT_PATTERNS:
                for match in pattern.finditer(body):
                    try:
                        value = match.group(1).strip()
                        if self._is_valid_endpoint(value):
                            finding = self._add_finding(
                                "endpoints",
                                value,
                                source_name,
                                host_header,
                                origin_header,
                                referer_header,
                                match.start(1),
                            )
                            if finding:
                                new_findings.append(finding)
                    except (IndexError, Exception) as e:
                        continue
        except Exception as e:
            self._log("Error in endpoint extraction: " + str(e))

        # 2. URLs
        try:
            for pattern in URL_PATTERNS:
                for match in pattern.finditer(body):
                    try:
                        value = (
                            match.group(1).strip()
                            if match.lastindex
                            else match.group(0).strip()
                        )
                        start_offset = (
                            match.start(1) if match.lastindex else match.start(0)
                        )
                        if self._is_valid_url(value):
                            finding = self._add_finding(
                                "urls",
                                value,
                                source_name,
                                host_header,
                                origin_header,
                                referer_header,
                                start_offset,
                            )
                            if finding:
                                new_findings.append(finding)
                    except (IndexError, Exception) as e:
                        continue
        except Exception as e:
            self._log("Error in URL extraction: " + str(e))

        # 3. Secrets
        try:
            for pattern, _ in SECRET_PATTERNS:
                for match in pattern.finditer(body):
                    try:
                        value = (
                            match.group(1).strip()
                            if match.lastindex
                            else match.group(0).strip()
                        )
                        start_offset = (
                            match.start(1) if match.lastindex else match.start(0)
                        )
                        if self._is_valid_secret(value):
                            finding = self._add_finding(
                                "secrets",
                                value,
                                source_name,
                                host_header,
                                origin_header,
                                referer_header,
                                start_offset,
                            )
                            if finding:
                                new_findings.append(finding)
                    except (IndexError, Exception) as e:
                        continue
        except Exception as e:
            self._log("Error in secret extraction: " + str(e))

        # 4. Emails
        try:
            for match in EMAIL_PATTERN.finditer(body):
                try:
                    value = match.group(1).strip()
                    if self._is_valid_email(value):
                        finding = self._add_finding(
                            "emails",
                            value,
                            source_name,
                            host_header,
                            origin_header,
                            referer_header,
                            match.start(1),
                        )
                        if finding:
                            new_findings.append(finding)
                except (IndexError, Exception) as e:
                    continue
        except Exception as e:
            self._log("Error in email extraction: " + str(e))

        # 5. Files (sensitive file references)
        try:
            for pattern in FILE_PATTERNS:
                for match in pattern.finditer(body):
                    value = (
                        match.group(1).strip()
                        if match.lastindex
                        else match.group(0).strip()
                    )
                    start_offset = match.start(1) if match.lastindex else match.start(0)

                    if self._is_valid_file(value):
                        finding = self._add_finding(
                            "files",
                            value,
                            source_name,
                            host_header,
                            origin_header,
                            referer_header,
                            start_offset,
                        )
                        if finding:
                            new_findings.append(finding)

        except Exception as e:
            self._log("Error in file extraction: " + str(e))

        # Update UI
        if new_findings:
            self._log("Found %d new items" % len(new_findings))
            self.panel.add_findings(new_findings, source_name)
        else:
            self._log("No new findings")

    def _add_finding(
        self,
        category,
        value,
        source,
        host_header,
        origin_header,
        referer_header,
        offset=0,
    ):
        """Add a finding if not duplicate."""
        key = category + ":" + value
        if key in self.seen_values:
            return None

        self.seen_values.add(key)
        finding = {
            "category": category,
            "value": value,
            "source": source,
            "host_header": host_header,
            "origin_header": origin_header,
            "referer_header": referer_header,
            "offset": offset,
        }
        self.all_findings.append(finding)
        return finding

    def get_source_code(self, source_name):
        """Retrieve source code for a given source name."""
        return self.source_map.get(source_name, "")

    def _is_valid_endpoint(self, value):
        """Strict endpoint validation - reject noise."""
        if not value or len(value) < 3:
            return False

        # Check exact matches first
        if value in NOISE_STRINGS:
            return False

        # Check noise patterns
        for pattern in NOISE_PATTERNS:
            if pattern.search(value):
                return False

        # Must start with / and have some path
        if not value.startswith("/"):
            return False

        # Skip if just a single segment with no meaning
        parts = value.split("/")
        if len(parts) < 2 or all(len(p) < 2 for p in parts if p):
            return False

        return True

    def _is_valid_url(self, value):
        """Strict URL validation."""
        if not value or len(value) < 15:
            return False

        val_lower = value.lower()

        # Check for noise domains
        for domain in NOISE_DOMAINS:
            if domain in val_lower:
                return False

        # Skip if contains placeholder patterns
        if "{" in value or "undefined" in val_lower or "null" in val_lower:
            return False

        # Skip data URIs
        if val_lower.startswith("data:"):
            return False

        # Skip if ends with common static extensions
        if any(
            val_lower.endswith(ext)
            for ext in [".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ttf"]
        ):
            return False

        return True

    def _is_valid_secret(self, value):
        """Validate secrets."""
        if not value or len(value) < 10:
            return False

        val_lower = value.lower()

        # Filter placeholders
        if any(
            x in val_lower
            for x in ["example", "placeholder", "your", "xxxx", "test", "your-"]
        ):
            return False

        # Filter common character sets
        if "abcdefg" in val_lower or "0123456" in val_lower:
            return False

        # Filter GTM/CamelCase noise (Google Tag Manager, common JS events)
        if any(
            value.startswith(x)
            for x in [
                "enableAuto",
                "unsubscribe",
                "onElement",
                "onForm",
                "onYouTube",
                "crossContainer",
                "js",
            ]
        ):
            return False

        # Filter strings that are too "regular" (mostly repetition)
        if len(set(value)) < 6:
            return False

        # Skip if it looks like a hex string that is too regular (like a color or padding)
        if all(c in "0123456789abcdefABCDEF" for c in value) and len(set(value)) < 4:
            return False

        return True

    def _is_valid_email(self, value):
        """Validate emails."""
        if not value or "@" not in value:
            return False

        val_lower = value.lower()
        domain = value.split("@")[-1].lower()

        if domain in {"example.com", "test.com", "domain.com", "placeholder.com"}:
            return False

        if any(x in val_lower for x in ["example", "test", "placeholder", "noreply"]):
            return False

        return True

    def _is_valid_file(self, value):
        """Validate file references."""
        if not value or len(value) < 3:
            return False

        val_lower = value.lower()

        # Skip common JS/build files
        if any(
            x in val_lower
            for x in [
                "package.json",
                "tsconfig.json",
                "webpack",
                "babel",
                "eslint",
                "prettier",
                "node_modules",
                ".min.",
                "polyfill",
                "vendor",
                "chunk",
                "bundle",
            ]
        ):
            return False

        # Skip source maps
        if val_lower.endswith(".map"):
            return False

        # Skip common locale/language files
        if val_lower.endswith(".json") and len(value.split("/")[-1]) <= 7:
            return False

        return True

    def clear_results(self):
        self.all_findings = []
        self.seen_values = set()
        self.source_map = {}

    def get_all_findings(self):
        return self.all_findings


class AnalyzeAction(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
        try:
            messages = self.invocation.getSelectedMessages()
            for msg in messages:
                try:
                    self.extender.analyze_response(msg)
                except Exception as e:
                    self.extender._log("Error analyzing response: " + str(e))
        except Exception as e:
            if self.extender:
                self.extender._log("Action error: " + str(e))
