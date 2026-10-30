/** How long a key outlives its day: a sixth of a day, at most ten minutes. Shared by the gateway and /app. */
export const graceSeconds = (cfg: { epochSeconds: number }) => Math.min(600, Math.floor(cfg.epochSeconds / 6));
