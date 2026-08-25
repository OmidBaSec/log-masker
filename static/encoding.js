// Text-encoding detection for uploaded log files.
//
// `FileReader.readAsText` assumes UTF-8. Windows produces plenty of logs that
// are not: Event Viewer exports, `Get-WinEvent | Out-File`, IIS logs and most
// PowerShell redirections default to UTF-16 LE, usually with a BOM and always
// with CRLF line endings. Decoded as UTF-8 those become mojibake full of NUL
// characters — which this app then rejected as "a binary file".
//
// Detection is a pure function over the raw bytes so it can be tested without a
// browser (see test_frontend.js); the actual decode is left to TextDecoder.

(function (root) {
  "use strict";

  // Sniff the first bytes of a file. Returns a TextDecoder label, or
  // "utf-32le"/"utf-32be" for encodings TextDecoder cannot handle.
  function detectEncoding(bytes) {
    const len = bytes.length;
    if (len >= 4 && bytes[0] === 0xff && bytes[1] === 0xfe &&
        bytes[2] === 0x00 && bytes[3] === 0x00) return "utf-32le";
    if (len >= 4 && bytes[0] === 0x00 && bytes[1] === 0x00 &&
        bytes[2] === 0xfe && bytes[3] === 0xff) return "utf-32be";
    if (len >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb &&
        bytes[2] === 0xbf) return "utf-8";
    if (len >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) return "utf-16le";
    if (len >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) return "utf-16be";

    // No BOM — common for `Out-File -Encoding unicode` and for files that have
    // been concatenated. Text that is mostly ASCII encoded as UTF-16 carries a
    // NUL in every second byte; which half tells us the byte order.
    const sample = Math.min(len, 4096);
    let evenNul = 0, oddNul = 0;
    for (let i = 0; i < sample; i++) {
      if (bytes[i] === 0) {
        if (i % 2) oddNul++; else evenNul++;
      }
    }
    const pairs = sample / 2;
    if (pairs >= 8) {
      if (oddNul > pairs * 0.3 && evenNul <= pairs * 0.05) return "utf-16le";
      if (evenNul > pairs * 0.3 && oddNul <= pairs * 0.05) return "utf-16be";
    }
    return "utf-8";
  }

  // CRLF and bare CR both become LF, so masking, previews and the placeholder
  // offsets all see one line ending. A leading BOM character is dropped.
  function normalizeText(text) {
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    return text.replace(/\r\n?/g, "\n");
  }

  // Decode a File's ArrayBuffer into normalized text.
  // Returns {text, encoding, hadCrlf} or {error} for what we cannot read.
  function decodeLogBytes(buffer) {
    const bytes = new Uint8Array(buffer);
    const encoding = detectEncoding(bytes);
    if (encoding === "utf-32le" || encoding === "utf-32be") {
      return { error: "UTF-32 files are not supported — re-save the log as " +
                      "UTF-8 or UTF-16." };
    }
    let text;
    try {
      text = new TextDecoder(encoding).decode(bytes);
    } catch (e) {
      return { error: "Could not decode this file as text (" + encoding + ")." };
    }
    const hadCrlf = text.indexOf("\r\n") !== -1;
    return { text: normalizeText(text), encoding: encoding, hadCrlf: hadCrlf };
  }

  const api = { detectEncoding, normalizeText, decodeLogBytes };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.LogEncoding = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
