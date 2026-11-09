import { useEffect } from "react";
import { useLocation } from "react-router-dom";

const siteUrl = ((import.meta.env.VITE_SITE_URL as string | undefined) ?? window.location.origin).replace(/\/+$/, "");

const publicRoutes: Record<string, { title: string; description: string }> = {
  "/": {
    title: "King Malhare | Know your weaknesses before attackers do",
    description:
      "Self-hosted vulnerability assessment and penetration testing platform with real scanners, authorization gates, evidence and remediation guidance.",
  },
  "/login": {
    title: "Sign in | King Malhare",
    description: "Sign in to the King Malhare security assessment console.",
  },
  "/register": {
    title: "Create a workspace | King Malhare",
    description: "Create a King Malhare workspace and start an authorized security assessment.",
  },
  "/api-docs": {
    title: "API documentation | King Malhare",
    description:
      "Scoped REST API for the King Malhare assessment engine. Sessions for the console, bearer keys for automation and OpenAPI 3.1 documentation.",
  },
  "/privacy": {
    title: "Privacy Policy | King Malhare",
    description: "How this self-hosted King Malhare instance handles account, assessment, evidence and audit data.",
  },
  "/terms": {
    title: "Terms of Service | King Malhare",
    description: "Authorized testing only. Terms for using this self-hosted King Malhare security assessment instance.",
  },
};

function ensureMeta(name: string, content: string, property = false) {
  const selector = property ? `meta[property="${name}"]` : `meta[name="${name}"]`;
  let element = document.head.querySelector<HTMLMetaElement>(selector);
  if (!element) {
    element = document.createElement("meta");
    element.setAttribute(property ? "property" : "name", name);
    document.head.appendChild(element);
  }
  element.setAttribute("content", content);
}

function ensureCanonical(href: string) {
  let element = document.head.querySelector<HTMLLinkElement>('link[rel="canonical"]');
  if (!element) {
    element = document.createElement("link");
    element.rel = "canonical";
    document.head.appendChild(element);
  }
  element.href = href;
}

export function SeoManager() {
  const location = useLocation();

  useEffect(() => {
    const path = location.pathname;
    const route = publicRoutes[path];
    const isPublic = Boolean(route);
    const title = route?.title ?? "King Malhare console";
    const description =
      route?.description ??
      "King Malhare security assessment console. Authorized testing only. Findings, evidence, remediation and reports are private to your organization.";
    const canonical = `${siteUrl}${path === "/" ? "/" : path}`;

    document.title = title;
    ensureMeta("description", description);
    ensureMeta("robots", isPublic ? "index, follow, max-image-preview:large, max-snippet:-1" : "noindex, nofollow");
    ensureCanonical(canonical);
    ensureMeta("og:title", title, true);
    ensureMeta("og:description", description, true);
    ensureMeta("og:url", canonical, true);
    ensureMeta("og:image", `${siteUrl}/og-image.png`, true);
    ensureMeta("og:type", "website", true);
    ensureMeta("twitter:card", "summary_large_image");
    ensureMeta("twitter:title", title);
    ensureMeta("twitter:description", description);
    ensureMeta("twitter:image", `${siteUrl}/og-image.png`);
  }, [location.pathname]);

  return null;
}
