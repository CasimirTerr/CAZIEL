// Browser checks for docs/index.html.
// Everything the page shows has to come from the engine's output in docs/data: the scan,
// the fix, and the live stream classified by `caziel watch`. This loads the page in
// Chromium, runs the live view, a replay, and the Claude chat against a mocked API.
const http = require("http");
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const ROOT = path.join(__dirname, "..", "..", "docs");
const read = (f) => JSON.parse(fs.readFileSync(path.join(ROOT, "data", f)));
const DATA = { before: read("before.json"), after: read("after.json"), live: read("live.json") };
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".json": "application/json", ".png": "image/png" };

function serve() {
  const server = http.createServer((req, res) => {
    const rel = decodeURIComponent(req.url.split("?")[0]).replace(/^\/+/, "") || "index.html";
    const file = path.join(ROOT, rel);
    if (!file.startsWith(ROOT) || !fs.existsSync(file)) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { "content-type": TYPES[path.extname(file)] || "application/octet-stream" });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((r) => server.listen(0, () => r(server)));
}

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${ok ? "" : "  " + detail}`);
  if (!ok) failures++;
}
const canHurt = (a) => a.worst.ratio > 1 && a.findings.some((f) => !f.accepted);

(async () => {
  const server = await serve();
  const url = `http://127.0.0.1:${server.address().port}/index.html`;
  const browser = await chromium.launch({ args: ["--use-gl=swiftshader", "--enable-webgl", "--ignore-gpu-blocklist"] });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));

  // A fake Claude API: first a tool call, then an answer.
  let apiCalls = 0;
  await page.route("https://api.anthropic.com/v1/messages", async (route) => {
    apiCalls++;
    const body = JSON.parse(route.request().postData());
    const sawTools = Array.isArray(body.tools) && body.tools.some((t) => t.name === "focus_robot");
    const content = apiCalls === 1
      ? [{ type: "tool_use", id: "tu_1", name: "focus_robot", input: { thing: "kx1-07" } }]
      : [{ type: "text", text: `**kx1-07** was hit by a prompt injection. tools=${sawTools}` }];
    await route.fulfill({ status: 200, contentType: "application/json",
      body: JSON.stringify({ content, stop_reason: apiCalls === 1 ? "tool_use" : "end_turn" }) });
  });

  await page.goto(url);
  await page.waitForSelector("body[data-ready='1']", { timeout: 20000 });

  // Static numbers match the engine
  check("hurt count", (await page.textContent("[data-stat=hurt]")).startsWith(`${DATA.before.actors.filter(canHurt).length} of`));
  check("worst ratio", (await page.textContent("[data-stat=worst]")).includes(`${Math.round(DATA.before.summary.worst.ratio)}×`));
  check("actor list", (await page.locator(".actor").count()) === DATA.before.actors.length);
  check("3D running", !(await page.isVisible("#fallback")));

  // Live: the feed fills, and every item says exactly what `caziel watch` said
  await page.click(".speedctl button[data-rate='10']");
  await page.waitForFunction(() => document.querySelectorAll("#feed li").length >= 8, null, { timeout: 20000 });
  const items = await page.$$eval("#feed li", (lis) => lis.slice(0, 8).map((li) => ({ i: Number(li.dataset.i), text: li.textContent })));
  check("feed matches watcher", items.every(({ i, text }) => text.includes(DATA.live.before[i].title) && text.includes(DATA.live.before[i].topic)),
    JSON.stringify(items.slice(0, 2)));
  const firstCrit = DATA.live.before.find((v) => v.severity === "critical");
  await page.waitForSelector(".toast", { timeout: 30000 });
  const toast = await page.textContent(".toast b");
  const highTitles = DATA.live.before.filter((v) => ["high", "critical"].includes(v.severity)).map((v) => v.title);
  check("alert toast", highTitles.includes(toast), toast);
  await page.waitForFunction((t) => [...document.querySelectorAll(".toast b")].some((b) => b.textContent === t), firstCrit.title, { timeout: 30000 });
  check("critical alert fired", true);
  check("alert counter", Number(await page.textContent("#c-alerts")) >= 1);
  check("3D tag shown", (await page.locator(".tag3d").count()) >= 1);

  // After the fix: same shift, the dangerous commands are blocked
  await page.click(".toggle button[data-mode=after]");
  await page.click(".speedctl button[data-rate='10']");
  const blockedTitle = DATA.live.after.find((v, i) => DATA.live.before[i].severity === "critical").title;
  await page.waitForFunction((t) => [...document.querySelectorAll("#feed li .what")].some((w) => w.textContent.startsWith(t)), blockedTitle, { timeout: 30000 });
  check("after: attack blocked in feed", true);
  check("after: no critical in feed", (await page.locator("#feed li.critical").count()) === 0);
  check("after: blocked counter", Number(await page.textContent("#c-blocked")) >= 1);

  // Replay view still works
  await page.click(".toggle button[data-mode=before]");
  await page.click(".actor[data-key='agent:dispatch-agent']");
  check("replay controls", await page.isVisible("#play-base"));
  await page.click("#play-base");
  await page.waitForSelector("#banner.show", { timeout: 15000 });
  const agent = DATA.before.actors.find((a) => a.key === "agent:dispatch-agent");
  const baseExp = agent.exposure.base.slice().sort((x, y) => y.ratio - x.ratio)[0];
  check("replay impact energy", (await page.textContent("#banner .t")).includes(baseExp.energy_j.toFixed(1)));
  await page.click(".actor[data-key='principal:site-supervisor-role']");
  await page.click("#play-base");
  await page.waitForSelector("#banner.show", { timeout: 30000 });
  check("guarded nav stops", (await page.textContent("#banner .t")).includes("Stopped by the collision monitor"));
  await page.click("#back-live");
  check("back to live", await page.isVisible("#feed"));

  // Claude chat over the API path, with a tool call
  check("key form offered", await page.isVisible("#keyform"));
  await page.fill("#apikey", "sk-ant-test");
  await page.click("#keyform button");
  await page.fill("#q", "What happened to kx1-07?");
  await page.click("#send");
  await page.waitForFunction(() => /prompt injection/.test(document.querySelector("#msgs").textContent), null, { timeout: 15000 });
  check("chat answer rendered", (await page.textContent("#msgs")).includes("kx1-07 was hit"));
  check("chat tool call shown", (await page.textContent("#msgs")).includes("focus_robot"));
  check("chat sent tools", (await page.textContent("#msgs")).includes("tools=true"));

  // Tables
  check("changes table", (await page.locator("#changes-table tbody tr").count()) === DATA.after.changes.length);
  check("region table", (await page.locator("#region-table tbody tr").count()) === DATA.before.fleet.body_regions.length);
  check("no console errors", errors.length === 0, errors.join(" | "));

  if (process.env.SHOT) {
    const shot = process.env.SHOT;
    const p2 = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    await p2.goto(url);
    await p2.waitForSelector("body[data-ready='1']");
    await p2.click(".speedctl button[data-rate='10']");
    await p2.waitForFunction(() => [...document.querySelectorAll(".toast b")].some((b) => /speed limits lifted|skips the collision/.test(b.textContent)), null, { timeout: 40000 });
    await p2.waitForTimeout(1800);
    await p2.addStyleTag({ content: "header.top{display:none!important}" });
    await (await p2.$("#demo")).screenshot({ path: shot });
    await p2.click(".actor[data-key='agent:dispatch-agent']");
    await p2.click("#play-base");
    await p2.waitForSelector("#banner.show", { timeout: 15000 });
    await p2.waitForTimeout(500);
    await (await p2.$("#demo")).screenshot({ path: shot.replace(".png", "-replay.png") });
    await p2.addStyleTag({ content: "header.top{display:flex!important}" });
    await p2.evaluate(() => window.scrollTo(0, 0));
    await p2.screenshot({ path: shot.replace(".png", "-hero.png") });
  }
  await browser.close();
  server.close();
  console.log(failures ? `\n${failures} check(s) failed` : "\nall web checks passed");
  process.exit(failures ? 1 : 0);
})();
