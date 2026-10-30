// Mainnet launch constants (v2, question packs), the same numbers engine/scripts/launch.ts passes to
// `initialize` or `reconfigure`. Before launch the app shows these with zero totals; after launch it
// reads them from the Config account instead.
export const LAUNCH = {
  epochSeconds: 86_400, // one day: keys are made for a day, purchases last `maxEpochs` days
  rate: 2_000n, // USDC base units per question: 0.002 USDC, 500 questions per USDC
  limit: 65_535, // most tickets one membership can hold (the circuit allows below 2^16)
  maxEpochs: 365, // a purchase or top-up keeps the membership valid for a year
  minQuestions: 250, // smallest purchase the program accepts

  burnBps: 2000, // a fifth of every purchase goes to the burn vault
  slashBurnBps: 5000, // unused since v2, kept for the account layout
};

// What the app sells, over and above the program's own floor: nothing below 5 USDC.
export const MIN_BUY = 2_500;
