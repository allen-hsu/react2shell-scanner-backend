"""
React2Shell Scanner - FastAPI Backend
CVE-2025-55182 & CVE-2025-66478 Detection API
"""

import sys
from pathlib import Path

# Add parent directory to path to import scanner
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional
from enum import Enum

from scanner import check_vulnerability, normalize_host

app = FastAPI(
    title="React2Shell Scanner API",
    description="API for detecting CVE-2025-55182 & CVE-2025-66478 vulnerabilities in Next.js applications",
    version="1.0.0",
)

# CORS configuration - adjust in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanMode(str, Enum):
    RCE = "rce"
    SAFE = "safe"
    VERCEL_BYPASS = "vercel-bypass"


class ScanRequest(BaseModel):
    """Request model for single host scan"""
    host: str = Field(..., description="Target URL/host to scan", examples=["https://example.com"])
    mode: ScanMode = Field(default=ScanMode.RCE, description="Scan mode")
    paths: Optional[list[str]] = Field(default=None, description="Custom paths to test", examples=[["/", "/_next"]])
    timeout: int = Field(default=10, ge=1, le=60, description="Request timeout in seconds")
    verify_ssl: bool = Field(default=False, description="Verify SSL certificates")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    windows: bool = Field(default=False, description="Use Windows PowerShell payload")
    waf_bypass: bool = Field(default=False, description="Enable WAF bypass mode")
    waf_bypass_size_kb: int = Field(default=128, ge=1, le=1024, description="WAF bypass junk data size in KB")
    custom_headers: Optional[dict[str, str]] = Field(default=None, description="Custom HTTP headers")


class ScanResult(BaseModel):
    """Response model for scan result"""
    host: str
    vulnerable: Optional[bool]
    status_code: Optional[int]
    error: Optional[str]
    final_url: Optional[str]
    tested_url: Optional[str]
    timestamp: str


class BatchScanRequest(BaseModel):
    """Request model for batch scan"""
    hosts: list[str] = Field(..., min_length=1, max_length=100, description="List of hosts to scan")
    mode: ScanMode = Field(default=ScanMode.RCE, description="Scan mode")
    paths: Optional[list[str]] = Field(default=None, description="Custom paths to test")
    timeout: int = Field(default=10, ge=1, le=60, description="Request timeout in seconds")
    verify_ssl: bool = Field(default=False, description="Verify SSL certificates")
    windows: bool = Field(default=False, description="Use Windows PowerShell payload")
    waf_bypass: bool = Field(default=False, description="Enable WAF bypass mode")


class BatchScanResult(BaseModel):
    """Response model for batch scan"""
    total: int
    vulnerable_count: int
    results: list[ScanResult]


@app.get("/")
async def root():
    """Health check endpoint"""
    return {"status": "ok", "service": "React2Shell Scanner API"}


@app.post("/api/scan", response_model=ScanResult)
async def scan_single_host(request: ScanRequest):
    """
    Scan a single host for CVE-2025-55182/CVE-2025-66478 vulnerability.

    - **host**: Target URL (e.g., https://example.com)
    - **mode**: Detection mode (rce, safe, or vercel-bypass)
    - **paths**: Custom paths to test (default: ["/"])
    """
    try:
        # Determine scan parameters based on mode
        safe_check = request.mode == ScanMode.SAFE
        vercel_waf_bypass = request.mode == ScanMode.VERCEL_BYPASS

        # Adjust timeout for WAF bypass
        timeout = request.timeout
        if request.waf_bypass and timeout == 10:
            timeout = 20

        result = check_vulnerability(
            host=request.host,
            timeout=timeout,
            verify_ssl=request.verify_ssl,
            follow_redirects=request.follow_redirects,
            custom_headers=request.custom_headers,
            safe_check=safe_check,
            windows=request.windows,
            waf_bypass=request.waf_bypass,
            waf_bypass_size_kb=request.waf_bypass_size_kb,
            vercel_waf_bypass=vercel_waf_bypass,
            paths=request.paths,
        )

        return ScanResult(
            host=result["host"],
            vulnerable=result["vulnerable"],
            status_code=result["status_code"],
            error=result["error"],
            final_url=result["final_url"],
            tested_url=result["tested_url"],
            timestamp=result["timestamp"],
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/batch", response_model=BatchScanResult)
async def scan_batch_hosts(request: BatchScanRequest):
    """
    Scan multiple hosts for vulnerabilities.

    Limited to 100 hosts per request for API safety.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    safe_check = request.mode == ScanMode.SAFE
    vercel_waf_bypass = request.mode == ScanMode.VERCEL_BYPASS

    timeout = request.timeout
    if request.waf_bypass and timeout == 10:
        timeout = 20

    results = []
    vulnerable_count = 0

    def scan_host(host: str) -> dict:
        return check_vulnerability(
            host=host,
            timeout=timeout,
            verify_ssl=request.verify_ssl,
            safe_check=safe_check,
            windows=request.windows,
            waf_bypass=request.waf_bypass,
            vercel_waf_bypass=vercel_waf_bypass,
            paths=request.paths,
        )

    # Use thread pool for concurrent scanning
    with ThreadPoolExecutor(max_workers=min(10, len(request.hosts))) as executor:
        futures = {executor.submit(scan_host, host): host for host in request.hosts}

        for future in as_completed(futures):
            result = future.result()
            results.append(ScanResult(
                host=result["host"],
                vulnerable=result["vulnerable"],
                status_code=result["status_code"],
                error=result["error"],
                final_url=result["final_url"],
                tested_url=result["tested_url"],
                timestamp=result["timestamp"],
            ))
            if result["vulnerable"]:
                vulnerable_count += 1

    return BatchScanResult(
        total=len(results),
        vulnerable_count=vulnerable_count,
        results=results,
    )


@app.get("/api/validate")
async def validate_host(host: str):
    """Validate and normalize a host URL"""
    normalized = normalize_host(host)
    if not normalized:
        raise HTTPException(status_code=400, detail="Invalid host")
    return {"original": host, "normalized": normalized}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
