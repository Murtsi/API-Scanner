import { useMemo, useState } from "react";
import Header from "./components/Header.jsx";
import ScannerPanel from "./components/ScannerPanel.jsx";
import ResultsPanel from "./components/ResultsPanel.jsx";
import RulesPanel from "./components/RulesPanel.jsx";

const PATTERNS = [
  {
    name: "Generic API Key",
    severity: "warning",
    regex: /(?:api[_-]?key|apikey|api_key)\s*[:=]\s*["'`]?([A-Za-z0-9\-_]{16,})["'`]?/gi,
    example: "api_key=xxxxxxxxxxxxxxxx",
  },
  {
    name: "AWS Access Key",
    severity: "danger",
    regex: /AKIA[0-9A-Z]{16}/g,
    example: "AKIAIOSFODNN7EXAMPLE",
  },
  {
    name: "AWS Secret Key",
    severity: "danger",
    regex: /(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[:=]\s*["'`]?([A-Za-z0-9/+=]{40})["'`]?/gi,
    example: "aws_secret_access_key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  },
  {
    name: "JWT Token",
    severity: "warning",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    example: "eyJ...eyJ...XXX",
  },
  {
    name: "Bearer Token",
    severity: "warning",
    regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g,
    example: "Bearer xxxxx",
  },
  {
    name: "Stripe Live Key",
    severity: "danger",
    regex: /sk_live_[0-9a-zA-Z]{24,}/g,
    example: "sk_live_...",
  },
  {
    name: "Google API Key",
    severity: "warning",
    regex: /AIzaSy[A-Za-z0-9_-]{33}/g,
    example: "AIzaSy...",
  },
  {
    name: "Slack Token",
    severity: "danger",
    regex: /xox[baprs]-[A-Za-z0-9-]{10,48}/g,
    example: "xoxb-...",
  },
  {
    name: "Private Key Block",
    severity: "danger",
    regex: /-----BEGIN(?:[ A-Z]*)PRIVATE KEY-----[\s\S]*?-----END(?:[ A-Z]*)PRIVATE KEY-----/g,
    example: "-----BEGIN PRIVATE KEY-----",
  },
  {
    name: "Password Assignment",
    severity: "warning",
    regex: /(?:password|passwd|pwd)\s*[:=]\s*["'`]?([^\s"'`]{6,})["'`]?/gi,
    example: "password=supersecret",
  },
  {
    name: "GitHub Token",
    severity: "danger",
    regex: /gh[pousr]_[A-Za-z0-9]{36,}/g,
    example: "ghp_...",
  },
  {
    name: "GitLab Token",
    severity: "danger",
    regex: /glpat-[A-Za-z0-9_-]{20,}/g,
    example: "glpat-...",
  },
  {
    name: "Firebase Server Key",
    severity: "warning",
    regex: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}/g,
    example: "AAAA...:...",
  },
  {
    name: "Twilio API Key",
    severity: "danger",
    regex: /SK[0-9a-fA-F]{32}/g,
    example: "SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  },
  {
    name: "SendGrid API Key",
    severity: "danger",
    regex: /SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g,
    example: "SG.xxx.xxx",
  },
  {
    name: "Mailgun API Key",
    severity: "warning",
    regex: /key-[0-9a-fA-F]{32}/g,
    example: "key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  },
  {
    name: "Heroku API Key",
    severity: "danger",
    regex: /heroku[a-z0-9]{20,}/gi,
    example: "heroku...",
  },
  {
    name: "Stripe Test Key",
    severity: "warning",
    regex: /sk_test_[0-9a-zA-Z]{24,}/g,
    example: "sk_test_...",
  },
  {
    name: "Azure Storage Key",
    severity: "warning",
    regex: /AccountKey=([A-Za-z0-9+/=]{88})/g,
    example: "AccountKey=...",
  },
  {
    name: "JWT Refresh Token",
    severity: "warning",
    regex: /refresh_token\s*[:=]\s*["'`]?([A-Za-z0-9_-]{20,})["'`]?/gi,
    example: "refresh_token=...",
  },
  {
    name: "Suspicious Key Assignment",
    severity: "warning",
    regex: /(?:api[_-]?key|secret|token|access[_-]?key|private[_-]?key)\s*[:=]\s*["'`]?([A-Za-z0-9+/=_-]{24,})["'`]?/gi,
    example: "token=...",
  },
  {
    name: "High-Entropy String",
    severity: "warning",
    regex: /[A-Za-z0-9+/=_-]{40,}/g,
    example: "<long random string>",
  },
];

export default function App() {
  const [urlsInput, setUrlsInput] = useState("");
  const [scanSummary, setScanSummary] = useState("Idle");
  const [statusRows, setStatusRows] = useState([]);
  const [results, setResults] = useState([]);
  const patterns = useMemo(() => PATTERNS, []);

  const urls = useMemo(() => {
    return urlsInput
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
  }, [urlsInput]);

  const updateStatus = (url, status, badge) => {
    setStatusRows((prev) => {
      const existing = prev.find((row) => row.url === url);
      if (existing) {
        return prev.map((row) =>
          row.url === url ? { ...row, status, badge } : row
        );
      }
      return [...prev, { url, status, badge }];
    });
  };

  const extractMatches = (content) => {
    return patterns
      .map((rule) => {
        const matches = [...content.matchAll(rule.regex)];
        if (!matches.length) return null;
        return {
          rule: rule.name,
          severity: rule.severity,
          matches: matches.map((match) => match[0]).slice(0, 6),
          total: matches.length,
        };
      })
      .filter(Boolean);
  };

  const scanUrl = async (url) => {
    updateStatus(url, "Scanning", "warning");
    try {
      const response = await fetch(url, { mode: "cors" });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const text = await response.text();
      const findings = extractMatches(text);
      updateStatus(url, "Done", "success");
      setResults((prev) => [
        ...prev,
        {
          url,
          findings,
          error: null,
        },
      ]);
    } catch (error) {
      updateStatus(url, "Failed", "danger");
      setResults((prev) => [
        ...prev,
        {
          url,
          findings: [],
          error: error.message,
        },
      ]);
    }
  };

  const startScan = async () => {
    if (!urls.length) {
      setScanSummary("Add at least one URL");
      return;
    }

    setResults([]);
    setStatusRows([]);
    setScanSummary(`Scanning ${urls.length} URL${urls.length > 1 ? "s" : ""}...`);

    for (const url of urls) {
      await scanUrl(url);
    }

    setScanSummary("Scan complete");
  };

  const clearAll = () => {
    setUrlsInput("");
    setStatusRows([]);
    setResults([]);
    setScanSummary("Idle");
  };

  return (
    <div className="page">
      <Header />
      <div className="container">
        <section className="card">
          <ScannerPanel
            urlsInput={urlsInput}
            setUrlsInput={setUrlsInput}
            scanSummary={scanSummary}
            statusRows={statusRows}
            onScan={startScan}
            onClear={clearAll}
          />
          <ResultsPanel results={results} />
        </section>
        <RulesPanel patterns={patterns} />
      </div>
      <footer>Built for quick reconnaissance. Always handle discoveries responsibly.</footer>
    </div>
  );
}
