// Starts the gateway: first teach Node how the site's files import each other, then load the server.
// Done here rather than with `node --import` because worker threads inherit command-line flags, and the
// prover's workers must start plain.
import { registerHooks } from "node:module";
import { resolve, load } from "./loader.mjs";

registerHooks({ resolve, load });
await import("./server.ts");
