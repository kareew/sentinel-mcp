import https from "node:https";
import http from "node:http";
import { URL } from "node:url";

interface TechDetection {
  category: string;
  technology: string;
  confidence: "high" | "medium" | "low";
  evidence: string;
}

interface TechFingerprintResult {
  url: string;
  technologies: TechDetection[];
  serverInfo: {
    server: string | null;
    poweredBy: string | null;
    framework: string | null;
  };
  securityImplications: string[];
  summary: string;
}

function fetchPage(targetUrl: string): Promise<{ headers: Record<string, string>; body: string; statusCode: number }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const client = parsed.protocol === "https:" ? https : http;

    const req = client.get(
      targetUrl,
      {
        timeout: 15000,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; Sentinel-MCP/1.0; SecurityScanner)",
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
      },
      (res) => {
        // Follow redirects
        if (res.statusCode && [301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
          const redirectUrl = res.headers.location.startsWith("http")
            ? res.headers.location
            : new URL(res.headers.location, targetUrl).toString();
          fetchPage(redirectUrl).then(resolve).catch(reject);
          return;
        }

        const headers: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (value) headers[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
        }

        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          // Limit body to 100KB
          if (body.length < 100_000) body += chunk;
        });
        res.on("end", () => resolve({ headers, body, statusCode: res.statusCode ?? 0 }));
      }
    );

    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timed out"));
    });
  });
}

const HEADER_PATTERNS: Array<{
  header: string;
  pattern: RegExp;
  category: string;
  technology: string;
}> = [
  { header: "server", pattern: /nginx/i, category: "Web Server", technology: "Nginx" },
  { header: "server", pattern: /apache/i, category: "Web Server", technology: "Apache" },
  { header: "server", pattern: /cloudflare/i, category: "CDN/WAF", technology: "Cloudflare" },
  { header: "server", pattern: /microsoft-iis/i, category: "Web Server", technology: "Microsoft IIS" },
  { header: "server", pattern: /litespeed/i, category: "Web Server", technology: "LiteSpeed" },
  { header: "server", pattern: /openresty/i, category: "Web Server", technology: "OpenResty" },
  { header: "x-powered-by", pattern: /php/i, category: "Language", technology: "PHP" },
  { header: "x-powered-by", pattern: /asp\.net/i, category: "Framework", technology: "ASP.NET" },
  { header: "x-powered-by", pattern: /express/i, category: "Framework", technology: "Express.js" },
  { header: "x-powered-by", pattern: /next\.js/i, category: "Framework", technology: "Next.js" },
  { header: "x-drupal/i", pattern: /./i, category: "CMS", technology: "Drupal" },
  { header: "x-generator", pattern: /wordpress/i, category: "CMS", technology: "WordPress" },
  { header: "x-generator", pattern: /drupal/i, category: "CMS", technology: "Drupal" },
  { header: "cf-ray", pattern: /./i, category: "CDN/WAF", technology: "Cloudflare" },
  { header: "x-amz-cf-id", pattern: /./i, category: "CDN", technology: "AWS CloudFront" },
  { header: "x-vercel-id", pattern: /./i, category: "Platform", technology: "Vercel" },
  { header: "x-served-by", pattern: /cache/i, category: "CDN", technology: "Fastly" },
  { header: "fly-request-id", pattern: /./i, category: "Platform", technology: "Fly.io" },
  { header: "x-render-origin-server", pattern: /./i, category: "Platform", technology: "Render" },
];

const BODY_PATTERNS: Array<{
  pattern: RegExp;
  category: string;
  technology: string;
  confidence: "high" | "medium" | "low";
}> = [
  { pattern: /wp-content|wp-includes|wordpress/i, category: "CMS", technology: "WordPress", confidence: "high" },
  { pattern: /Drupal\.settings/i, category: "CMS", technology: "Drupal", confidence: "high" },
  { pattern: /Joomla!/i, category: "CMS", technology: "Joomla", confidence: "high" },
  { pattern: /react/i, category: "JS Framework", technology: "React", confidence: "medium" },
  { pattern: /__next/i, category: "Framework", technology: "Next.js", confidence: "high" },
  { pattern: /__nuxt/i, category: "Framework", technology: "Nuxt.js", confidence: "high" },
  { pattern: /ng-version/i, category: "JS Framework", technology: "Angular", confidence: "high" },
  { pattern: /vue\.js|vue@/i, category: "JS Framework", technology: "Vue.js", confidence: "medium" },
  { pattern: /svelte/i, category: "JS Framework", technology: "Svelte", confidence: "medium" },
  { pattern: /jquery/i, category: "JS Library", technology: "jQuery", confidence: "medium" },
  { pattern: /bootstrap/i, category: "CSS Framework", technology: "Bootstrap", confidence: "medium" },
  { pattern: /tailwindcss|tailwind/i, category: "CSS Framework", technology: "Tailwind CSS", confidence: "medium" },
  { pattern: /google-analytics|gtag|UA-\d+/i, category: "Analytics", technology: "Google Analytics", confidence: "high" },
  { pattern: /googletagmanager/i, category: "Analytics", technology: "Google Tag Manager", confidence: "high" },
  { pattern: /shopify/i, category: "E-commerce", technology: "Shopify", confidence: "high" },
  { pattern: /woocommerce/i, category: "E-commerce", technology: "WooCommerce", confidence: "high" },
  { pattern: /recaptcha/i, category: "Security", technology: "Google reCAPTCHA", confidence: "high" },
  { pattern: /cloudflare/i, category: "CDN/WAF", technology: "Cloudflare", confidence: "low" },
];

export async function fingerprintTech(url: string): Promise<TechFingerprintResult> {
  let targetUrl = url;
  if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
    targetUrl = `https://${targetUrl}`;
  }

  const { headers, body } = await fetchPage(targetUrl);

  const detections = new Map<string, TechDetection>();

  // Check headers
  for (const check of HEADER_PATTERNS) {
    const headerValue = headers[check.header];
    if (headerValue && check.pattern.test(headerValue)) {
      const key = `${check.category}:${check.technology}`;
      if (!detections.has(key)) {
        detections.set(key, {
          category: check.category,
          technology: check.technology,
          confidence: "high",
          evidence: `Header '${check.header}: ${headerValue}'`,
        });
      }
    }
  }

  // Check body patterns
  for (const check of BODY_PATTERNS) {
    if (check.pattern.test(body)) {
      const key = `${check.category}:${check.technology}`;
      if (!detections.has(key)) {
        detections.set(key, {
          category: check.category,
          technology: check.technology,
          confidence: check.confidence,
          evidence: `Pattern match in HTML body`,
        });
      }
    }
  }

  const technologies = Array.from(detections.values());

  // Security implications
  const securityImplications: string[] = [];

  if (headers.server) {
    securityImplications.push(
      `Server header reveals: "${headers.server}" — version information aids attacker reconnaissance. Suppress or genericize this header.`
    );
  }

  if (headers["x-powered-by"]) {
    securityImplications.push(
      `X-Powered-By reveals: "${headers["x-powered-by"]}" — remove this header to reduce attack surface.`
    );
  }

  const hasCMS = technologies.some((t) => t.category === "CMS");
  if (hasCMS) {
    const cms = technologies.find((t) => t.category === "CMS");
    securityImplications.push(
      `${cms?.technology} CMS detected — ensure it's updated and admin paths are protected.`
    );
  }

  const hasWAF = technologies.some((t) => t.category === "CDN/WAF");
  if (!hasWAF) {
    securityImplications.push("No WAF/CDN detected — consider adding Cloudflare or similar for DDoS and bot protection.");
  }

  let summary = `Detected ${technologies.length} technologies across ${new Set(technologies.map((t) => t.category)).size} categories. `;
  const categories = [...new Set(technologies.map((t) => t.category))];
  summary += `Categories: ${categories.join(", ")}. `;
  summary += `${securityImplications.length} security implication(s) noted.`;

  return {
    url: targetUrl,
    technologies,
    serverInfo: {
      server: headers.server || null,
      poweredBy: headers["x-powered-by"] || null,
      framework: technologies.find((t) => t.category === "Framework")?.technology || null,
    },
    securityImplications,
    summary,
  };
}
