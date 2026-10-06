import { defineConfig, devices } from "@playwright/test";

import { DB, DB_DIR, PYTHON, ROOT } from "./e2e/env";

// The smoke test needs the admin API on 8766, where the dashboard looks for it, with an empty
// database, and the built dashboard on 3000. scripts/demo.py then fills the database with real
// MCP calls through the gateway. PLAYWRIGHT_CHROMIUM_EXECUTABLE points at a Chromium other than
// the one `npx playwright install chromium` downloads.
export default defineConfig({
  testDir: "e2e",
  timeout: 120_000,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://127.0.0.1:3000",
    viewport: { width: 1280, height: 800 },
    launchOptions: { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined },
    trace: "retain-on-failure",
  },
  webServer: [
    {
      command: `rm -rf "${DB_DIR}" && "${PYTHON}" -m gateway.admin_api --port 8766 --db "${DB}"`,
      cwd: ROOT,
      url: "http://127.0.0.1:8766/tools",
      reuseExistingServer: false, // another admin API would read another database
      stdout: "ignore",
    },
    {
      command: "npm run build && npm run start",
      url: "http://127.0.0.1:3000",
      reuseExistingServer: !process.env.CI,
      timeout: 180_000,
    },
  ],
});
