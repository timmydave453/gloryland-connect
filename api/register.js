export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ok:false,error:"Method not allowed"});
  const endpoint = process.env.GAS_ENDPOINT;
  const secret = process.env.GAS_SHARED_SECRET;
  if (!endpoint || !secret) return res.status(503).json({ok:false,error:"Registration is being configured. Please try again later."});
  try {
    const payload = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
    if (!payload || typeof payload !== "object" || !payload.id || !payload.fullName)
      return res.status(400).json({ok:false,error:"Invalid registration details"});
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 18000);
    let upstream;
    try {
      upstream = await fetch(endpoint, {
        method:"POST",
        headers:{"Content-Type":"text/plain;charset=utf-8"},
        body:JSON.stringify({secret,payload}),
        redirect:"follow",
        signal:controller.signal
      });
    } finally { clearTimeout(timeout); }
    const raw = await upstream.text();
    let result;
    try { result = JSON.parse(raw); }
    catch { return res.status(502).json({ok:false,error:"Google Apps Script did not return a valid response"}); }
    if (!upstream.ok || !result.ok) return res.status(502).json({ok:false,error:result.error || "Registration was not confirmed"});
    return res.status(200).json({ok:true,duplicate:!!result.duplicate});
  } catch {
    return res.status(502).json({ok:false,error:"Registration service temporarily unavailable. Please retry."});
  }
}
