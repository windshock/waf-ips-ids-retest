/**
 * TC-27 busboy echo backend (:3000)
 *
 * Parses multipart/form-data with busboy (same parser as Next.js/Vercel).
 * Returns parsed fields, raw body hex, and headers so the probe can verify
 * what the backend actually received after WAF inspection.
 */
const http = require("http");
const { Readable } = require("stream");
const busboy = require("busboy");

function respond(res, payload) {
  const body = Buffer.from(JSON.stringify(payload, null, 2), "utf-8");
  res.writeHead(200, {
    "Content-Type": "application/json",
    "Content-Length": String(body.length),
    "X-TC27-Backend": "busboy-echo",
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const rawBody = Buffer.concat(chunks);
    const contentType = req.headers["content-type"] || "";

    const base = {
      method: req.method,
      path: req.url,
      headers: req.headers,
      raw_body_hex: rawBody.toString("hex"),
      raw_body_bytes: rawBody.length,
      parser: "busboy",
    };

    if (req.method !== "POST" || !contentType.includes("multipart/form-data")) {
      return respond(res, { ...base, parsed_fields: {} });
    }

    const fields = {};
    let parseError = null;

    try {
      const bb = busboy({ headers: req.headers, defParamCharset: "utf8" });

      bb.on("field", (name, value, info) => {
        // store raw value + encoding info so we can see what busboy decoded
        fields[name] = value;
        if (info && info.encoding && info.encoding !== "7bit") {
          fields[`${name}__encoding`] = info.encoding;
        }
        if (info && info.mimeType && info.mimeType !== "text/plain") {
          fields[`${name}__mime`] = info.mimeType;
        }
      });

      bb.on("finish", () => {
        const result = { ...base, parsed_fields: fields };
        if (parseError) result.parse_error = parseError;
        respond(res, result);
      });

      bb.on("error", (err) => {
        respond(res, { ...base, parsed_fields: fields, parse_error: err.message });
      });

      const readable = new Readable();
      readable.push(rawBody);
      readable.push(null);
      readable.pipe(bb);
    } catch (err) {
      respond(res, { ...base, parsed_fields: {}, parse_error: err.message });
    }
  });
});

const port = parseInt(process.env.PORT || "3000", 10);
server.listen(port, "0.0.0.0", () => {
  console.log(`TC-27 busboy echo backend listening on :${port}`);
});
