// Records docs/demo.gif: scripts/demo.py at a watchable pace, with captions, then ffmpeg.
//
//     RECORD_DEMO=1 npx playwright test demo-recording
import { spawn, spawnSync } from "node:child_process";
import path from "node:path";

import { expect, test, type Locator, type Page } from "@playwright/test";

import { DB, PYTHON, ROOT } from "./env";

const SIZE = { width: 1280, height: 720 };
const GIF = path.join(ROOT, "docs", "demo.gif");

test.skip(!process.env.RECORD_DEMO, "Set RECORD_DEMO=1 to record docs/demo.gif");
test.use({ viewport: SIZE, video: { mode: "on", size: SIZE } });

/** A caption pinned to the bottom of the page. */
async function caption(page: Page, text: string) {
  await page.evaluate((text) => {
    let el = document.getElementById("demo-caption");
    if (!el) {
      el = document.createElement("div");
      el.id = "demo-caption";
      Object.assign(el.style, {
        position: "fixed", left: "50%", bottom: "28px", transform: "translateX(-50%)", zIndex: "50",
        maxWidth: "1040px", padding: "12px 20px", borderRadius: "10px", background: "rgba(24, 24, 27, 0.92)",
        color: "white", font: "500 19px/1.4 system-ui, sans-serif", textAlign: "center",
        boxShadow: "0 8px 24px rgba(0, 0, 0, 0.25)",
      });
      document.body.appendChild(el);
    }
    document.body.style.paddingBottom = "140px"; // room to scroll content clear of the caption
    el.textContent = text;
  }, text);
}

/** Outline what is about to be clicked, so the viewer can follow. */
async function press(target: Locator) {
  await target.evaluate((el: HTMLElement) => {
    el.dataset.demoPressed = "";
    el.style.outline = "3px solid #f59e0b";
    el.style.outlineOffset = "2px";
    el.style.borderRadius = "4px";
  });
  await target.page().waitForTimeout(900);
  await target.click();
  // Links in the header outlive client-side navigation, so take the outline off again. Not through
  // `target`: a locator waits for its element, and a link in the page just left is gone for good.
  await target.page().evaluate(() =>
    document.querySelectorAll<HTMLElement>("[data-demo-pressed]").forEach((el) => {
      el.style.outline = "";
      delete el.dataset.demoPressed;
    }),
  );
}

test("record the demo", async ({ page }) => {
  test.setTimeout(180_000);
  const feed = page.locator("tbody");
  const row = (tool: string, decision: string) =>
    feed
      .getByRole("row")
      .filter({ hasText: tool })
      .filter({ has: page.getByText(decision, { exact: true }) });

  await page.goto("/");
  await caption(page, "An AI agent triages a suspicious VPN login. Every MCP tool call it makes goes through MCP Guard.");
  await page.waitForTimeout(2500);

  const demo = spawn(PYTHON, ["scripts/demo.py", "--pace", "0.9", "--db", DB], {
    cwd: ROOT,
    env: { ...process.env, EMBEDDING_PROVIDER: "hash" },
  });
  const exited = new Promise<number | null>((resolve) => demo.on("exit", resolve));
  try {
    await expect(feed.getByRole("row")).toHaveCount(9, { timeout: 60_000 });
    await caption(page, "Lookups are allowed. Out-of-scope clients, bad arguments and protected targets are blocked.");
    await page.waitForTimeout(3500);

    await caption(page, "One change record carried an injected instruction. The output scanner redacted it.");
    await press(row("search_change_records", "ALLOW_REDACTED").getByRole("link"));
    const findings = page.getByRole("heading", { name: "Scanner findings" });
    await expect(findings).toBeVisible();
    await caption(page, "One change record carried an injected instruction. The output scanner redacted it.");
    await page.waitForTimeout(1200);
    await page.evaluate(() => window.scrollTo({ top: document.body.scrollHeight, behavior: "smooth" }));
    await page.waitForTimeout(4000);

    await page.getByRole("link", { name: "← All calls" }).click();
    await caption(page, "The write that instruction asked for was refused: dana.oliveira is a protected admin.");
    await press(row("disable_account", "BLOCK_RULE").getByRole("link"));
    await expect(page.getByText("it is tagged admin")).toBeVisible();
    await caption(page, "The write that instruction asked for was refused: dana.oliveira is a protected admin.");
    await page.waitForTimeout(3500);

    await caption(page, "Disabling the compromised account is high risk, so it waits for a human.");
    await press(page.getByRole("link", { name: /Pending/ }));
    const card = page.locator("article").filter({ hasText: "zara.quintero" });
    await expect(card).toBeVisible();
    await caption(page, "Disabling the compromised account is high risk, so it waits for a human.");
    await page.waitForTimeout(1500);
    await card.getByLabel("Note").pressSequentially("Confirmed with Zara by phone: not her login", { delay: 35 });
    await press(card.getByRole("button", { name: "Approve" }));
    await expect(page.getByRole("status")).toBeVisible();
    expect(await exited).toBe(0);
    await page.waitForTimeout(1500);

    await press(page.getByRole("link", { name: "Calls" }));
    await caption(page, "Approved: the gateway runs the call, and the audit log records who approved it and why.");
    await expect(feed.getByRole("row")).toHaveCount(10);
    await page.waitForTimeout(1200);
    await press(row("disable_account", "ALLOW").getByRole("link"));
    await expect(page.getByText("Held for human approval: approved")).toBeVisible();
    await caption(page, "Approved: the gateway runs the call, and the audit log records who approved it and why.");
    await page.waitForTimeout(4000);
  } finally {
    demo.kill();
  }

  // The video is complete once the page closes.
  await page.close();
  const webm = test.info().outputPath("demo.webm");
  await page.video()!.saveAs(webm);
  const palette = "fps=10,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];"
    + "[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle";
  const ffmpeg = spawnSync("ffmpeg", ["-y", "-loglevel", "error", "-ss", "1", "-i", webm, "-vf", palette, GIF]);
  expect(ffmpeg.status, `ffmpeg failed: ${ffmpeg.stderr}`).toBe(0);
});
