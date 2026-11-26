import {describe, expect, it} from "vitest";
import {createMemoryRateLimiter} from "./rate-limit";

describe("in-process rate limiting", () => {
  it("isolates categories, rejects at the threshold and resets the window", async () => {
    let now = 59_000;
    const limit = createMemoryRateLimiter(() => now);
    expect(await limit("local:upload", 1)).toEqual({allowed: true, retryAfter: 1});
    expect(await limit("local:upload", 1)).toEqual({allowed: false, retryAfter: 1});
    expect((await limit("local:auth", 1)).allowed).toBe(true);
    now = 60_001;
    expect(await limit("local:upload", 1)).toEqual({allowed: true, retryAfter: 60});
  });

  it("bounds in-memory state for new clients", async () => {
    const limit = createMemoryRateLimiter(() => 0, 1);
    expect((await limit("client-a:upload", 5)).allowed).toBe(true);
    expect((await limit("client-b:upload", 5)).allowed).toBe(false);
    expect((await limit("client-a:upload", 5)).allowed).toBe(true);
  });
});
