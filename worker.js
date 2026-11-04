// Personal gambling DNS filter (DNS-over-HTTPS) for Cloudflare Workers.
// Blocks names that match the rules in blocked-names.txt (same syntax as dnscrypt-proxy)
// and forwards everything else to Mullvad's family filter, which also blocks gambling.

const LIST_URL = "https://raw.githubusercontent.com/darwish1016/dns-filter-list/main/blocked-names.txt";
const UPSTREAM = "https://family.dns.mullvad.net/dns-query";
const LIST_CACHE_SECONDS = 300;

let rules = null;
let rulesLoadedAt = 0;

// ---------- rule parsing and matching (dnscrypt-proxy style) ----------
function globToRegex(glob) {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") re += ".*";
    else if (c === "?") re += ".";
    else if (c === "[") {
      const end = glob.indexOf("]", i);
      if (end === -1) { re += "\\["; continue; }
      re += glob.slice(i, end + 1).replace(/\\/g, "\\\\");
      i = end;
    } else re += c.replace(/[.+^${}()|\\\/]/g, "\\$&");
  }
  return new RegExp("^" + re + "$");
}

function parseRules(text) {
  const parsed = { exact: new Set(), suffix: new Set(), patterns: [] };
  for (let line of text.split("\n")) {
    line = line.replace(/#.*$/, "").trim().toLowerCase();
    if (!line) continue;
    if (line.startsWith("regex:")) {
      try { parsed.patterns.push(new RegExp(line.slice(6).trim().replace(/^`|`$/g, ""))); } catch (e) {}
    } else if (line.startsWith("=")) {
      parsed.exact.add(line.slice(1));
    } else if (/^\*\.[^*?\[]+$/.test(line)) {
      parsed.suffix.add(line.slice(2));
    } else if (/[*?\[]/.test(line)) {
      parsed.patterns.push(globToRegex(line));
    } else {
      parsed.suffix.add(line);
    }
  }
  return parsed;
}

function isBlocked(name, r) {
  name = name.toLowerCase().replace(/\.$/, "");
  if (r.exact.has(name)) return true;
  const labels = name.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    if (r.suffix.has(labels.slice(i).join("."))) return true;
  }
  return r.patterns.some((re) => re.test(name));
}

async function getRules() {
  const now = Date.now();
  if (rules && now - rulesLoadedAt < LIST_CACHE_SECONDS * 1000) return rules;
  try {
    const res = await fetch(LIST_URL + "?t=" + Math.floor(now / (LIST_CACHE_SECONDS * 1000)), {
      cf: { cacheTtl: LIST_CACHE_SECONDS },
    });
    if (res.ok) {
      rules = parseRules(await res.text());
      rulesLoadedAt = now;
    }
  } catch (e) {}
  return rules || parseRules("");
}

// ---------- minimal DNS wire-format helpers ----------
function readQuestion(buf) {
  if (buf.length < 12) return null;
  let off = 12;
  const labels = [];
  while (off < buf.length) {
    const len = buf[off];
    if (len === 0) { off++; break; }
    if (len > 63) return null;
    labels.push(String.fromCharCode(...buf.slice(off + 1, off + 1 + len)));
    off += 1 + len;
  }
  if (off + 4 > buf.length) return null;
  return { name: labels.join("."), qtype: (buf[off] << 8) | buf[off + 1], end: off + 4 };
}

function blockedResponse(query, q) {
  // NXDOMAIN answer that echoes the question
  const out = new Uint8Array(q.end);
  out.set(query.slice(0, q.end));
  const opcode = (query[2] >> 3) & 0x0f;
  const rd = query[2] & 0x01;
  out[2] = 0x80 | (opcode << 3) | rd; // QR=1, RD copied
  out[3] = 0x80 | 0x03;               // RA=1, RCODE=NXDOMAIN
  out[4] = 0; out[5] = 1;             // QDCOUNT=1
  out[6] = out[7] = out[8] = out[9] = out[10] = out[11] = 0;
  return out;
}

function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

const dnsHeaders = { "content-type": "application/dns-message", "cache-control": "max-age=60" };

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Human-readable check: /check?name=example.com
    if (url.pathname === "/check") {
      const name = (url.searchParams.get("name") || "").trim();
      const r = await getRules();
      return Response.json({ name, blocked: name ? isBlocked(name, r) : null,
        rules: r.exact.size + r.suffix.size + r.patterns.length });
    }

    if (url.pathname !== "/dns-query") return new Response("OK", { status: 200 });

    let query;
    if (request.method === "GET") {
      const dns = url.searchParams.get("dns");
      if (!dns) return new Response("missing dns parameter", { status: 400 });
      query = b64urlDecode(dns);
    } else if (request.method === "POST") {
      query = new Uint8Array(await request.arrayBuffer());
    } else {
      return new Response("method not allowed", { status: 405 });
    }

    const q = readQuestion(query);
    if (q && isBlocked(q.name, await getRules())) {
      return new Response(blockedResponse(query, q), { headers: dnsHeaders });
    }

    const upstream = await fetch(UPSTREAM, {
      method: "POST",
      headers: { "content-type": "application/dns-message", accept: "application/dns-message" },
      body: query,
    });
    return new Response(upstream.body, {
      status: upstream.status,
      headers: { "content-type": "application/dns-message" },
    });
  },
};
