"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"
import { Loader2, Search, Shield, AlertTriangle, XCircle, CheckCircle } from "lucide-react"

interface ScanResult {
  url: string
  threat_level: "HIGH" | "MEDIUM" | "LOW" | "CLEAN"
  malicious_count: number
  suspicious_count: number
  total_vendors: number
  confidence_score: number
  recommendation: string
  should_block: boolean
  analysis_date: string
}

export function ScannerForm() {
  const [url, setUrl] = useState("")
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || "Failed to scan URL")
      }

      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred")
    } finally {
      setLoading(false)
    }
  }

  const getThreatColor = (level: string) => {
    switch (level) {
      case "HIGH":
        return "text-destructive"
      case "MEDIUM":
        return "text-warning"
      case "LOW":
        return "text-accent"
      case "CLEAN":
        return "text-success"
      default:
        return "text-muted-foreground"
    }
  }

  const getThreatIcon = (level: string) => {
    switch (level) {
      case "HIGH":
        return <XCircle className="h-8 w-8 text-destructive" />
      case "MEDIUM":
        return <AlertTriangle className="h-8 w-8 text-warning" />
      case "LOW":
        return <Shield className="h-8 w-8 text-accent" />
      case "CLEAN":
        return <CheckCircle className="h-8 w-8 text-success" />
      default:
        return <Shield className="h-8 w-8 text-muted-foreground" />
    }
  }

  const getThreatBg = (level: string) => {
    switch (level) {
      case "HIGH":
        return "bg-destructive/10 border-destructive/20"
      case "MEDIUM":
        return "bg-warning/10 border-warning/20"
      case "LOW":
        return "bg-accent/10 border-accent/20"
      case "CLEAN":
        return "bg-success/10 border-success/20"
      default:
        return "bg-muted/10 border-border"
    }
  }

  return (
    <div className="space-y-6">
      {/* Input Form */}
      <Card className="bg-card border-border p-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="url" className="text-sm font-medium text-card-foreground">
              Enter URL to scan
            </label>
            <div className="flex gap-2">
              <Input
                id="url"
                type="text"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={loading}
                className="flex-1 bg-background border-input text-foreground placeholder:text-muted-foreground"
              />
              <Button
                type="submit"
                disabled={loading || !url.trim()}
                className="bg-primary text-primary-foreground hover:bg-primary/90"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Scanning
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4 mr-2" />
                    Scan URL
                  </>
                )}
              </Button>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            Enter any URL to check for phishing threats, malware, and other security risks.
          </p>
        </form>
      </Card>

      {/* Error State */}
      {error && (
        <Card className="bg-destructive/10 border-destructive/20 p-4">
          <div className="flex items-start gap-3">
            <XCircle className="h-5 w-5 text-destructive mt-0.5" />
            <div className="space-y-1">
              <p className="text-sm font-medium text-destructive">Scan Failed</p>
              <p className="text-sm text-destructive/80">{error}</p>
            </div>
          </div>
        </Card>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Threat Level Card */}
          <Card className={`${getThreatBg(result.threat_level)} p-6`}>
            <div className="flex items-start gap-4">
              <div className="mt-1">{getThreatIcon(result.threat_level)}</div>
              <div className="flex-1 space-y-3">
                <div>
                  <h3 className={`text-2xl font-bold ${getThreatColor(result.threat_level)}`}>
                    {result.threat_level} THREAT
                  </h3>
                  <p className="text-sm text-muted-foreground mt-1 font-mono break-all">{result.url}</p>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Malicious</p>
                    <p className="text-2xl font-bold text-foreground">{result.malicious_count}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Suspicious</p>
                    <p className="text-2xl font-bold text-foreground">{result.suspicious_count}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Total Vendors</p>
                    <p className="text-2xl font-bold text-foreground">{result.total_vendors}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Confidence</p>
                    <p className="text-2xl font-bold text-foreground">{result.confidence_score}%</p>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Recommendation Card */}
          <Card className="bg-card border-border p-6">
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-accent" />
                <h4 className="font-semibold text-card-foreground">Recommendation</h4>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed">{result.recommendation}</p>
              {result.should_block && (
                <div className="pt-2 border-t border-border">
                  <p className="text-sm font-medium text-destructive">⚠️ This URL should be blocked immediately</p>
                </div>
              )}
            </div>
          </Card>

          {/* Metadata */}
          <Card className="bg-card border-border p-4">
            <p className="text-xs text-muted-foreground">
              Scanned on {new Date(result.analysis_date).toLocaleString()} • Powered by VirusTotal API
            </p>
          </Card>
        </div>
      )}
    </div>
  )
}
