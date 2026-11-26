import {inflateSync} from "node:zlib";
import jsQR from "jsqr";
import {decodeCode} from "./index";

const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
const MAX_INFLATED_BYTES = 24 * 1024 * 1024;
const MAX_TEXT_STREAM_BYTES = 2 * 1024 * 1024;
const MAX_STREAMS = 128;
const MAX_QR_PIXELS = 8 * 1024 * 1024;

export type PdfCodeDiscovery = {
  codes: string[];
  qrUrls: string[];
  unrelatedQrPayloads: string[];
};

export function extractCodeFromText(input: string): string[] {
  const matches = input.toUpperCase().match(/D1-[A-Z2-7]{32}/g) || [];
  const valid = new Set<string>();
  for (const m of matches) {
    try {
      decodeCode(m);
      valid.add(m);
    } catch {
      // Ignore non-canonical matches
    }
  }
  return [...valid];
}

export function extractVerificationCodesFromPdf(bytes: Uint8Array): PdfCodeDiscovery {
  const codes = new Set<string>();
  const qrUrls = new Set<string>();
  const unrelatedQrPayloads = new Set<string>();
  if (bytes.byteLength > MAX_UPLOAD_BYTES) return {codes: [], qrUrls: [], unrelatedQrPayloads: []};
  const buf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const str = buf.toString("latin1");
  for (const c of extractCodeFromText(str)) codes.add(c);

  const streamRegex = />>\s{0,64}stream\r?\n/g;
  let remainingInflated = MAX_INFLATED_BYTES;
  let remainingPixels = MAX_QR_PIXELS;
  let streams = 0;
  const inflate = (raw: Uint8Array, limit: number) => {
    const maxOutputLength = Math.min(limit, remainingInflated);
    try {
      const result = inflateSync(raw, {maxOutputLength});
      remainingInflated -= result.length;
      return result;
    } catch (error) {
      if ((error as {code?: string}).code === "ERR_BUFFER_TOO_LARGE") {
        remainingInflated -= maxOutputLength;
      }
      return undefined;
    }
  };
  let match: RegExpExecArray | null;
  while (streams++ < MAX_STREAMS && remainingInflated > 0 && (match = streamRegex.exec(str)) !== null) {
    const dictStart = str.lastIndexOf("<<", match.index);
    const dataStart = streamRegex.lastIndex;
    const endIdx = str.indexOf("endstream", dataStart);
    if (endIdx < 0) break;
    streamRegex.lastIndex = endIdx + "endstream".length;
    if (dictStart < 0 || match.index - dictStart > 16_384) continue;
    const dict = str.slice(dictStart + 2, match.index);
    let sliceEnd = endIdx;
    if (str[sliceEnd - 1] === "\n") sliceEnd--;
    if (str[sliceEnd - 1] === "\r") sliceEnd--;
    const rawStream = buf.subarray(dataStart, sliceEnd);

    if (/\/Subtype\s*\/Image/.test(dict)) {
      const w = Number(dict.match(/\/Width\s+(\d+)/)?.[1]);
      const h = Number(dict.match(/\/Height\s+(\d+)/)?.[1]);
      const pixels = w * h;
      if (!w || !h || w > 2048 || h > 2048 || pixels > remainingPixels) continue;
      try {
        const inflated = inflate(rawStream, pixels * 4);
        if (!inflated) continue;
        let rgba: Uint8ClampedArray | null = null;
        if (inflated.length === w * h * 3) {
          rgba = new Uint8ClampedArray(w * h * 4);
          for (let i = 0, j = 0; i < inflated.length; i += 3, j += 4) {
            rgba[j] = inflated[i];
            rgba[j + 1] = inflated[i + 1];
            rgba[j + 2] = inflated[i + 2];
            rgba[j + 3] = 255;
          }
        } else if (inflated.length === w * h * 4) {
          rgba = new Uint8ClampedArray(inflated);
        } else if (inflated.length === w * h) {
          rgba = new Uint8ClampedArray(w * h * 4);
          for (let i = 0, j = 0; i < inflated.length; i++, j += 4) {
            rgba[j] = inflated[i];
            rgba[j + 1] = inflated[i];
            rgba[j + 2] = inflated[i];
            rgba[j + 3] = 255;
          }
        }
        if (rgba) {
          remainingPixels -= pixels;
          const decoded = jsQR(rgba, w, h);
          if (decoded?.data) {
            const found = extractCodeFromText(decoded.data);
            if (found.length > 0) {
              for (const c of found) codes.add(c);
              qrUrls.add(decoded.data);
            } else {
              unrelatedQrPayloads.add(decoded.data.slice(0, 200));
            }
          }
        }
      } catch {
        // Ignore non-deflate or masked image streams
      }
    } else if (/\/FlateDecode/.test(dict)) {
      const inflated = inflate(rawStream, MAX_TEXT_STREAM_BYTES);
      if (inflated) {
        for (const c of extractCodeFromText(inflated.toString("latin1"))) codes.add(c);
      }
    }
  }

  return {
    codes: [...codes],
    qrUrls: [...qrUrls],
    unrelatedQrPayloads: [...unrelatedQrPayloads],
  };
}
