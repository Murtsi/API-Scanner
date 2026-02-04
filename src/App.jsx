import { useMemo, useState } from "react";
import Header from "./components/Header.jsx";
import ScannerPanel from "./components/ScannerPanel.jsx";
import ResultsPanel from "./components/ResultsPanel.jsx";
import RulesPanel from "./components/RulesPanel.jsx";

const BASE_RULES = [
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
    name: "Stripe Test Key",
    severity: "warning",
    regex: /sk_test_[0-9a-zA-Z]{24,}/g,
    example: "sk_test_...",
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
];

const EXPOSED_PATHS = [
  "/.env",
  "/.env.local",
  "/.git/config",
  "/config.json",
  "/settings.json",
  "/swagger.json",
  "/openapi.json",
  "/swagger/v1/swagger.json",
  "/robots.txt",
  "/sitemap.xml",
  "/backup.zip",
  "/backup.tar.gz",
];

const MAX_ASSETS = 10;
const MAX_MATCHES = 6;
const MAX_ENTROPY_MATCHES = 8;
const ENTROPY_THRESHOLD = 3.6;

const safeRegex = (pattern, flags) => {
  try {
    const cleanFlags = flags.includes("g") ? flags : `${flags}g`;
    return new RegExp(pattern, cleanFlags);
  } catch {
    return null;
  }
};

const parseUrls = (value) =>
  value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

const getEntropy = (value) => {
  const counts = new Map();
  for (const char of value) {
    counts.set(char, (counts.get(char) || 0) + 1);
  }
  const length = value.length;
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
};

const buildCsv = (rows) =>
  rows
    .map((row) =>
      row
        .map((cell) => `"${String(cell).replace(/"/g, '""')}"`)
        .join(",")
    )
    .join("\n");

export default function App() {
  const [urlsInput, setUrlsInput] = useState("");
  const [scanSummary, setScanSummary] = useState("Idle");
  const [statusRows, setStatusRows] = useState([]);
  const [results, setResults] = useState([]);
  const [customRulesInput, setCustomRulesInput] = useState("");
  const [scanOptions, setScanOptions] = useState({
    scanAssets: true,
    checkExposed: true,
  });

  const urls = useMemo(() => parseUrls(urlsInput), [urlsInput]);

  const customRules = useMemo(() => {
    return customRulesInput
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line, index) => {
        let name = `Custom Rule ${index + 1}`;
        let patternText = line;
        let flags = "g";

        if (line.includes("::")) {
          const [left, right] = line.split("::").map((part) => part.trim());
          name = left || name;
          patternText = right || "";
        }

        if (!patternText) return null;

        if (patternText.startsWith("/") && patternText.lastIndexOf("/") > 0) {
          const lastSlash = patternText.lastIndexOf("/");
          flags = patternText.slice(lastSlash + 1) || "g";
          patternText = patternText.slice(1, lastSlash);
        }

        const regex = safeRegex(patternText, flags);
        if (!regex) return null;

        return {
          name,
          severity: "warning",
          regex,
          example: patternText,
        };
      })
      .filter(Boolean);
  }, [customRulesInput]);

  const rules = useMemo(() => [...BASE_RULES, ...customRules], [customRules]);

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

  const extractFindings = (content, sourceLabel) => {
    const matches = rules
      .map((rule) => {
        const found = [...content.matchAll(rule.regex)];
        if (!found.length) return null;
        return {
          rule: rule.name,
          severity: rule.severity,
          matches: found.map((match) => match[0]).slice(0, MAX_MATCHES),
          total: found.length,
          source: sourceLabel,
        };
      })
      .filter(Boolean);

    const entropyMatches = (content.match(/[A-Za-z0-9+/=_-]{40,}/g) || [])
      .filter((match) => getEntropy(match) >= ENTROPY_THRESHOLD)
      .slice(0, MAX_ENTROPY_MATCHES);

    if (entropyMatches.length) {
      matches.push({
        rule: "High-Entropy String",
        severity: "warning",
        matches: entropyMatches,
        total: entropyMatches.length,
        source: sourceLabel,
      });
    }

    return matches;
  };

  const extractAssets = (html, baseUrl) => {
    try {
      const doc = new DOMParser().parseFromString(html, "text/html");
      const scripts = Array.from(doc.querySelectorAll("script[src]")).map((el) => el.getAttribute("src"));
      const links = Array.from(doc.querySelectorAll("link[href]")).map((el) => el.getAttribute("href"));
      const candidates = [...scripts, ...links]
        .filter(Boolean)
        .filter((src) => src.endsWith(".js") || src.includes(".js?"));
      const urls = candidates.map((src) => new URL(src, baseUrl).toString());
      return Array.from(new Set(urls)).slice(0, MAX_ASSETS);
    } catch {
      return [];
    }
  };

  const checkExposedFiles = async (url) => {
    try {
      const origin = new URL(url).origin;
      const hits = [];

      for (const path of EXPOSED_PATHS) {
        const target = `${origin}${path}`;
        try {
          const response = await fetch(target, { method: "GET", mode: "cors" });
          if (response.ok) {
            hits.push({ path, status: response.status });
          }
        } catch {
          // ignore fetch errors
        }
      }

      return hits;
    } catch {
      return [];
    }
  };

  const scanTarget = async (url) => {
    updateStatus(url, "Scanning", "warning");

    try {
      const response = await fetch(url, { mode: "cors" });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const html = await response.text();
      const findings = extractFindings(html, "HTML");
      let assetsScanned = 0;
      let assetFindings = [];
      let exposedFiles = [];

      if (scanOptions.scanAssets) {
        const assetUrls = extractAssets(html, url);
        assetsScanned = assetUrls.length;

        for (const assetUrl of assetUrls) {
          try {
            const assetResponse = await fetch(assetUrl, { mode: "cors" });
            if (!assetResponse.ok) continue;
            const assetText = await assetResponse.text();
            assetFindings = assetFindings.concat(
              extractFindings(assetText, `Asset: ${assetUrl}`)
            );
          } catch {
            // ignore asset fetch errors
          }
        }
      }

      if (scanOptions.checkExposed) {
        exposedFiles = await checkExposedFiles(url);
      }

      updateStatus(url, "Done", "success");
      setResults((prev) => [
        ...prev,
        {
          url,
          findings: [...findings, ...assetFindings],
          assetsScanned,
          exposedFiles,
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
          assetsScanned: 0,
          exposedFiles: [],
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
      await scanTarget(url);
    }

    setScanSummary("Scan complete");
  };

  const clearAll = () => {
    setUrlsInput("");
    setStatusRows([]);
    setResults([]);
    setScanSummary("Idle");
  };

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(results, null, 2)], {
      type: "application/json",
    });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "scan-results.json";
    link.click();
  };

  const exportCsv = () => {
    const rows = [["URL", "Rule", "Severity", "Source", "Match"]];

    results.forEach((result) => {
      result.findings.forEach((finding) => {
        finding.matches.forEach((match) => {
          rows.push([
            result.url,
            finding.rule,
            finding.severity,
            finding.source,
            match,
          ]);
        });
      });
    });

    const blob = new Blob([buildCsv(rows)], { type: "text/csv" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "scan-results.csv";
    link.click();
  };

  return (
    <div className="page">
      <Header />
      <div className="container">
        <section className="card">
          <ScannerPanel
            urlsInput={urlsInput}
            setUrlsInput={setUrlsInput}
            customRulesInput={customRulesInput}
            setCustomRulesInput={setCustomRulesInput}
            scanOptions={scanOptions}
            setScanOptions={setScanOptions}
            scanSummary={scanSummary}
            statusRows={statusRows}
            onScan={startScan}
            onClear={clearAll}
            onExportJson={exportJson}
            onExportCsv={exportCsv}
          />
          <ResultsPanel results={results} />
        </section>
        <RulesPanel patterns={rules} />
      </div>
      <footer>Built for quick reconnaissance. Always handle discoveries responsibly.</footer>
    </div>
  );
}
