export const SITE = {
  name: "mayrun",
  url: "https://mayrun.dev",
  tagline: "Agents don’t run dangerous commands until mayrun says they may.",
  description:
    "Policy gate for coding-agent side effects. Evaluate shell commands against YAML policy, execute only when allowed, append hash-chained receipts.",
  github: "https://github.com/kiket-dev/mayrun",
  themeColor: "#E9EDF2",
} as const;

export const NAV = [
  { href: "/install", label: "Install" },
  { href: "/use-cases", label: "Use cases" },
  { href: "/packs", label: "Packs" },
  { href: "/docs", label: "Docs" },
  { href: "/pricing", label: "Pricing" },
] as const;

export const DOC_NAV = [
  {
    section: "start",
    label: "Start",
    items: [
      { slug: "install", title: "Install" },
      { slug: "quickstart", title: "Quickstart" },
    ],
  },
  {
    section: "guide",
    label: "Guides",
    items: [
      { slug: "architecture", title: "Architecture" },
      { slug: "policy", title: "Policy" },
      { slug: "mcp", title: "MCP & proxy" },
      { slug: "ci", title: "CI Action" },
    ],
  },
  {
    section: "reference",
    label: "Reference",
    items: [
      { slug: "license", title: "Pro license" },
      { slug: "sandbox", title: "Sandbox" },
    ],
  },
] as const;
