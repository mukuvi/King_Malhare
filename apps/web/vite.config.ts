import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { loadEnv, type Plugin } from "vite";

function seoFiles(siteUrl: string): Plugin {
  const base = siteUrl.replace(/\/+$/, "");
  return {
    name: "king-malhare-seo-files",
    apply: "build",
    closeBundle() {
      const outDir = resolve(process.cwd(), "dist");
      mkdirSync(outDir, { recursive: true });
      const today = new Date().toISOString().slice(0, 10);
      const publicUrls = ["/", "/login", "/register", "/privacy", "/terms", "/api-docs", "/api/v1/docs", "/api/v1/openapi.yaml"];
      const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${publicUrls
  .map(
    (path) => `  <url>
    <loc>${base}${path}</loc>
    <lastmod>${today}</lastmod>
    <changefreq>${path === "/" ? "weekly" : "monthly"}</changefreq>
    <priority>${path === "/" ? "1.0" : "0.7"}</priority>
  </url>`,
  )
  .join("\n")}
</urlset>
`;
      writeFileSync(resolve(outDir, "sitemap.xml"), sitemap);
      const robots = `User-agent: *
Allow: /
Allow: /privacy
Allow: /terms
Allow: /api/v1/docs
Allow: /api/v1/openapi.yaml
Disallow: /api/
Disallow: /dashboard
Disallow: /assets
Disallow: /scans
Disallow: /findings
Disallow: /reports
Disallow: /integrations
Disallow: /settings
Disallow: /organization
Disallow: /audit
Disallow: /notifications
Disallow: /intel
Disallow: /web-security
Disallow: /network-security
Disallow: /cloud-security
Disallow: /auth-testing
Sitemap: ${base}/sitemap.xml
`;
      writeFileSync(resolve(outDir, "robots.txt"), robots);
    },
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const siteUrl = env.VITE_SITE_URL || "https://kingmalhare.mukuvi.tech";
  return {
    plugins: [react(), seoFiles(siteUrl)],
    resolve: {
      alias: {
        "@": fileURLToPath(new URL("./src", import.meta.url)),
      },
    },
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: "http://localhost:8080",
          changeOrigin: false,
        },
      },
    },
    build: {
      sourcemap: false,
      chunkSizeWarningLimit: 900,
      rollupOptions: {
        output: {
          manualChunks: {
            charts: ["recharts"],
            motion: ["framer-motion"],
          },
        },
      },
    },
    test: {
      environment: "jsdom",
      setupFiles: "./src/test/setup.ts",
      css: true,
    },
  };
});
