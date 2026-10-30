// Lets plain Node run the site's gateway code as is: "@/x" means web/x, and imports written without
// an extension find their .ts or .tsx file, the way the Next.js build resolves them.
import { existsSync, statSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

const WEB = new URL("../web/", import.meta.url);
const EXTS = [".ts", ".tsx", "/index.ts"];

function withExtension(url) {
  const path = fileURLToPath(url);
  if (existsSync(path) && statSync(path).isFile()) return url;
  for (const ext of EXTS) if (existsSync(path + ext)) return pathToFileURL(path + ext).href;
  return url;
}

export function resolve(specifier, context, next) {
  if (specifier.startsWith("@/")) return next(withExtension(new URL(specifier.slice(2), WEB).href), context);
  const ours = context.parentURL?.startsWith("file:") && !context.parentURL.includes("/node_modules/");
  if (ours && (specifier.startsWith("./") || specifier.startsWith("../"))) {
    return next(withExtension(new URL(specifier, context.parentURL).href), context);
  }
  return next(specifier, context);
}

// The site's own .ts and .js files are ES modules; saying so up front saves Node from guessing each time.
export function load(url, context, next) {
  if (url.startsWith(WEB.href) && !url.includes("/node_modules/")) {
    if (/\.tsx?$/.test(url)) return next(url, { ...context, format: "module-typescript" });
    if (url.endsWith(".js")) return next(url, { ...context, format: "module" });
  }
  return next(url, context);
}
