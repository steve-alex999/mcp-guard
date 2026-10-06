import { spawn } from "node:child_process";

import { expect, test, type Page } from "@playwright/test";

import { DB, PYTHON, ROOT, SCREENSHOTS } from "./env";

/** The page down to the end of its content, for the README. */
async function shot(page: Page, name: string) {
  await page.locator("body").screenshot({ path: `${SCREENSHOTS}/${name}.png` });
}

test("calls reach the feed, and a held call can be approved", async ({ page }) => {
  // Ten MCP calls through the gateway; the last one waits for a human.
  const demo = spawn(PYTHON, ["scripts/demo.py", "--pace", "0", "--db", DB], {
    cwd: ROOT,
    env: { ...process.env, EMBEDDING_PROVIDER: "hash" },
  });
  let output = "";
  demo.stdout.on("data", (chunk) => (output += chunk));
  demo.stderr.on("data", (chunk) => (output += chunk));
  const exited = new Promise<number | null>((resolve) => demo.on("exit", resolve));

  try {
    // The feed polls the admin API every 2 s.
    await page.goto("/");
    const feed = page.locator("tbody");
    const row = (tool: string, decision: string) =>
      feed
        .getByRole("row")
        .filter({ hasText: tool })
        .filter({ has: page.getByText(decision, { exact: true }) });
    await expect(feed.getByText("BLOCK_NOT_ALLOWED")).toBeVisible({ timeout: 30_000 });
    await expect(feed.getByText("ALLOW_REDACTED")).toBeVisible();
    await expect(feed.getByText("BLOCK_RULE")).toHaveCount(2);

    // The write the injected instruction asked for, refused because the target is an admin.
    await row("disable_account", "BLOCK_RULE").getByRole("link").click();
    await expect(page.getByText("it is tagged admin, which the policy protects")).toBeVisible();
    await shot(page, "call-blocked");

    // The search that returned the planted change record: redacted, with the findings listed.
    await page.goto("/");
    await row("search_change_records", "ALLOW_REDACTED").getByRole("link").click();
    await expect(page.getByRole("heading", { name: "Scanner findings" })).toBeVisible();
    await expect(page.getByText(/\[REDACTED: /).first()).toBeVisible();
    await shot(page, "call-redacted");

    // The held disable_account, approved with a note.
    await page.goto("/pending");
    const card = page.locator("article").filter({ hasText: "zara.quintero" });
    await expect(card).toBeVisible({ timeout: 30_000 });
    await card.getByLabel("Note").fill("Confirmed with Zara by phone: not her login");
    await shot(page, "pending");
    await card.getByRole("button", { name: "Approve" }).click();
    await expect(page.getByRole("status")).toHaveText("Approved disable_account for claude-desktop.");

    // The gateway runs the approved call, and the demo ends.
    expect(await exited).toBe(0);
    expect(output).toMatch(/disable_account +ALLOW +Approved by dashboard: Confirmed with Zara/);

    await page.goto("/");
    await expect(feed.getByRole("row")).toHaveCount(10);
    await shot(page, "feed");

    await row("disable_account", "ALLOW").getByRole("link").click();
    await expect(page.getByText("Held for human approval: approved")).toBeVisible();
    await shot(page, "call-approved");

    await page.goto("/policy");
    await expect(page.getByRole("heading", { name: "Policy" })).toBeVisible();
    await shot(page, "policy");
  } finally {
    demo.kill();
  }
});
