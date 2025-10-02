import { ScannerForm } from "@/components/scanner-form"
import { Shield, AlertTriangle, CheckCircle, Info } from "lucide-react"

export default function Home() {
  return (
    <main className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-accent" />
            <h1 className="text-xl font-semibold text-foreground">Phishing URL Scanner</h1>
          </div>
          <div className="text-sm text-muted-foreground font-mono">Powered by VirusTotal</div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="container mx-auto px-4 py-16 md:py-24">
        <div className="max-w-4xl mx-auto text-center space-y-6">
          <h2 className="text-4xl md:text-6xl font-bold text-foreground text-balance">
            Detect phishing threats before they strike.
          </h2>
          <p className="text-lg md:text-xl text-muted-foreground text-pretty max-w-2xl mx-auto">
            Analyze suspicious URLs in real-time using VirusTotal's threat intelligence from 85+ security vendors. Get
            instant threat assessments and actionable recommendations.
          </p>
        </div>
      </section>

      {/* Scanner Section */}
      <section className="container mx-auto px-4 pb-16">
        <div className="max-w-4xl mx-auto">
          <ScannerForm />
        </div>
      </section>

      {/* Features Grid */}
      <section className="container mx-auto px-4 py-16 border-t border-border">
        <div className="grid md:grid-cols-3 gap-6 max-w-5xl mx-auto">
          <div className="bg-card border border-border rounded-lg p-6 space-y-3">
            <div className="h-10 w-10 rounded-lg bg-success/10 flex items-center justify-center">
              <CheckCircle className="h-5 w-5 text-success" />
            </div>
            <h3 className="text-lg font-semibold text-card-foreground">Real-time Analysis</h3>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Instant threat detection using VirusTotal's comprehensive database of known malicious URLs and domains.
            </p>
          </div>

          <div className="bg-card border border-border rounded-lg p-6 space-y-3">
            <div className="h-10 w-10 rounded-lg bg-warning/10 flex items-center justify-center">
              <AlertTriangle className="h-5 w-5 text-warning" />
            </div>
            <h3 className="text-lg font-semibold text-card-foreground">Multi-vendor Intelligence</h3>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Aggregated threat data from 85+ security vendors for comprehensive protection and accurate detection.
            </p>
          </div>

          <div className="bg-card border border-border rounded-lg p-6 space-y-3">
            <div className="h-10 w-10 rounded-lg bg-accent/10 flex items-center justify-center">
              <Info className="h-5 w-5 text-accent" />
            </div>
            <h3 className="text-lg font-semibold text-card-foreground">Actionable Reports</h3>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Detailed analysis with threat levels, confidence scores, and clear recommendations for response actions.
            </p>
          </div>
        </div>
      </section>
    </main>
  )
}
