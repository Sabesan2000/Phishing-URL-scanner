import { type NextRequest, NextResponse } from "next/server"

// Mock VirusTotal response for demonstration
// In production, this would call the actual Python scanner
function mockScanResult(url: string) {
  // Simulate different threat levels based on URL patterns
  const urlLower = url.toLowerCase()

  let malicious = 0
  let suspicious = 0
  let threat_level: "HIGH" | "MEDIUM" | "LOW" | "CLEAN" = "CLEAN"
  let recommendation = ""
  let should_block = false

  // Simulate threat detection
  if (urlLower.includes("phishing") || urlLower.includes("malware") || urlLower.includes("hack")) {
    malicious = Math.floor(Math.random() * 20) + 15
    suspicious = Math.floor(Math.random() * 10) + 5
    threat_level = "HIGH"
    recommendation =
      "CRITICAL: This URL has been flagged by multiple security vendors as malicious. Block immediately and report to your security team. Do not access this URL under any circumstances."
    should_block = true
  } else if (urlLower.includes("suspicious") || urlLower.includes("spam")) {
    malicious = Math.floor(Math.random() * 8) + 3
    suspicious = Math.floor(Math.random() * 8) + 5
    threat_level = "MEDIUM"
    recommendation =
      "WARNING: This URL shows suspicious characteristics. Exercise caution and verify the source before proceeding. Consider blocking if used in a corporate environment."
    should_block = false
  } else if (urlLower.includes("test") || urlLower.includes("example")) {
    malicious = Math.floor(Math.random() * 3)
    suspicious = Math.floor(Math.random() * 5) + 1
    threat_level = "LOW"
    recommendation =
      "CAUTION: Minor security concerns detected. The URL appears mostly safe but monitor for unusual activity. Proceed with standard security practices."
    should_block = false
  } else {
    malicious = 0
    suspicious = Math.floor(Math.random() * 2)
    threat_level = "CLEAN"
    recommendation =
      "SAFE: No significant threats detected. This URL appears to be legitimate based on current threat intelligence. Continue with normal security practices."
    should_block = false
  }

  const total_vendors = 85
  const flagged = malicious + suspicious
  const confidence_score = Math.min(Math.round((flagged / total_vendors) * 100), 100)

  return {
    url,
    threat_level,
    malicious_count: malicious,
    suspicious_count: suspicious,
    total_vendors,
    confidence_score,
    recommendation,
    should_block,
    analysis_date: new Date().toISOString(),
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { url } = body

    if (!url || typeof url !== "string") {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    // Validate URL format
    try {
      new URL(url)
    } catch {
      return NextResponse.json({ error: "Invalid URL format" }, { status: 400 })
    }

    // Simulate API delay
    await new Promise((resolve) => setTimeout(resolve, 1500))

    // In production, this would call the Python scanner:
    // const result = await fetch('http://python-scanner/scan', {
    //   method: 'POST',
    //   body: JSON.stringify({ url }),
    // })

    const result = mockScanResult(url)

    return NextResponse.json(result)
  } catch (error) {
    console.error("[v0] Scan error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
