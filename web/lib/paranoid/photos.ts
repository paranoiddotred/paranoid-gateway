// What a photo costs. A photo makes the model read about a thousand tokens more than a text question,
// so each one sent with a message spends PHOTO_QUESTIONS more questions. The browser pays that up front
// (app/app/App.tsx); the gateway counts the photos in a plain request, and for a sealed request, which it
// cannot open, it asks a floor by size, so photos cannot ride along for the price of text.

/** Questions one photo adds to a message. */
export const PHOTO_QUESTIONS = 2;
/** Photos sent with one message: the newest ones in the conversation (a scanned page counts as one). */
export const MAX_PHOTOS = 4;
/** Size of one photo as it leaves the browser (JPEG bytes, before base64). */
export const PHOTO_BYTES = 220_000;
/** Size of one scanned PDF page as it leaves: smaller than a photo, so four pages fit in one message. */
export const SCAN_BYTES = 145_000;
/** All the photos of one message together. A sealed or relayed question must stay under 1 MB, and a photo
 *  grows by a third as base64; this leaves room for the words. */
export const PHOTOS_BYTES = 600_000;

/** How many image parts OpenAI-style `messages` carry. */
export function photosIn(messages: unknown): number {
  if (!Array.isArray(messages)) return 0;
  let n = 0;
  for (const m of messages) {
    const c = (m as { content?: unknown })?.content;
    if (Array.isArray(c)) for (const part of c) if ((part as { type?: unknown })?.type === "image_url") n++;
  }
  return n;
}

/** The fewest extra questions a sealed request of `bytes` must carry. One photo seals to about 250 KB
 *  (gzip barely shrinks a JPEG), so each full 200 KB counts as a photo; text alone never gets near it. */
export const sealedPhotoFloor = (bytes: number) => Math.floor(bytes / 200_000) * PHOTO_QUESTIONS;
