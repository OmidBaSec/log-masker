// Checks for the browser-side log decoding.
// Run:  node test_frontend.js
//   or  /System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc test_frontend.js
//
// Windows logs arrive as UTF-16 with a BOM and CRLF far more often than anyone
// expects, and getting that wrong means the analyst either sees mojibake or is
// told their log is "a binary file". The detection is pure byte inspection, so
// it runs without a browser.

var LogEncoding;
var LogRender;
if (typeof require !== "undefined") {
    LogEncoding = require("./log_masker/static/encoding.js");
    LogRender = require("./log_masker/static/render.js");
} else {
    // JavaScriptCore: no module system, so evaluate the file into this scope.
    globalThis.module = undefined;
    eval(readFile("./log_masker/static/encoding.js"));   // eslint-disable-line no-eval
    eval(readFile("./log_masker/static/render.js"));     // eslint-disable-line no-eval
    LogEncoding = globalThis.LogEncoding;
    LogRender = globalThis.LogRender;
    if (typeof TextDecoder === "undefined") {
        globalThis.TextDecoder = function (encoding) {
            this.encoding = (encoding || "utf-8").toLowerCase();
        };
        globalThis.TextDecoder.prototype.decode = function (bytes) {
            var u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
            var s = "", i = 0;
            if (this.encoding === "utf-16le") {
                for (i = 0; i < u8.length; i += 2) {
                    s += String.fromCharCode(u8[i] | (u8[i + 1] << 8));
                }
                return s;
            }
            if (this.encoding === "utf-16be") {
                for (i = 0; i < u8.length; i += 2) {
                    s += String.fromCharCode((u8[i] << 8) | u8[i + 1]);
                }
                return s;
            }
            while (i < u8.length) {
                var b = u8[i++];
                if (b < 0x80) { s += String.fromCharCode(b); }
                else if (b < 0xe0) { s += String.fromCharCode(((b & 0x1f) << 6) | (u8[i++] & 0x3f)); }
                else if (b < 0xf0) { s += String.fromCharCode(((b & 0x0f) << 12) | ((u8[i++] & 0x3f) << 6) | (u8[i++] & 0x3f)); }
                else { s += String.fromCharCode(b); }
            }
            return s;
        };
    }
}

var failures = 0;
function check(name, cond) {
    print((cond ? "PASS" : "FAIL") + " - " + name);
    if (!cond) failures++;
}
if (typeof print === "undefined") { var print = console.log; }

// --- helpers ---------------------------------------------------------------
function bytesOf() {                     // bytesOf(0xff, 0xfe, ...)
    return new Uint8Array(Array.prototype.slice.call(arguments));
}

function asciiAsUtf16(str, bigEndian, bom) {
    var out = [];
    if (bom) out = bigEndian ? [0xfe, 0xff] : [0xff, 0xfe];
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        if (bigEndian) { out.push(0x00, c); } else { out.push(c, 0x00); }
    }
    return new Uint8Array(out);
}

function asciiAsUtf8(str, bom) {
    var out = bom ? [0xef, 0xbb, 0xbf] : [];
    for (var i = 0; i < str.length; i++) out.push(str.charCodeAt(i));
    return new Uint8Array(out);
}

var SAMPLE = "2026-06-09 10:31 user=jsmith from 10.4.2.19\r\nhost=ws07.acme.local\r\n";

// --- detection -------------------------------------------------------------
function testDetection() {
    var d = LogEncoding.detectEncoding;
    check("UTF-8 BOM is detected", d(asciiAsUtf8(SAMPLE, true)) === "utf-8");
    check("plain ASCII reads as UTF-8", d(asciiAsUtf8(SAMPLE, false)) === "utf-8");
    check("UTF-16 LE with BOM is detected",
          d(asciiAsUtf16(SAMPLE, false, true)) === "utf-16le");
    check("UTF-16 BE with BOM is detected",
          d(asciiAsUtf16(SAMPLE, true, true)) === "utf-16be");
    // PowerShell's `Out-File -Encoding unicode` often lands without a BOM.
    check("UTF-16 LE without a BOM is detected by NUL pattern",
          d(asciiAsUtf16(SAMPLE, false, false)) === "utf-16le");
    check("UTF-16 BE without a BOM is detected by NUL pattern",
          d(asciiAsUtf16(SAMPLE, true, false)) === "utf-16be");
    check("UTF-32 LE is identified (and refused later)",
          d(bytesOf(0xff, 0xfe, 0x00, 0x00, 0x41)) === "utf-32le");
    check("UTF-32 BE is identified",
          d(bytesOf(0x00, 0x00, 0xfe, 0xff, 0x41)) === "utf-32be");
    check("an empty file does not crash detection",
          d(new Uint8Array(0)) === "utf-8");
    check("a short file is not guessed as UTF-16",
          d(asciiAsUtf8("hi", false)) === "utf-8");
    // A UTF-8 log that merely contains a stray NUL must not be mistaken for
    // UTF-16 — that would garble the whole file.
    var withNul = asciiAsUtf8(SAMPLE, false);
    withNul[10] = 0x00;
    check("one stray NUL does not flip the guess to UTF-16",
          d(withNul) === "utf-8");
}

// --- real-world files that must NOT be mistaken for UTF-16 ----------------
function testBinaryAndNonAscii() {
    var d = LogEncoding.detectEncoding;

    // A PNG is full of NULs. If it were sniffed as UTF-16 it would decode to
    // NUL-free mojibake and sail past the app's "looks binary" check, landing
    // garbage in the textarea instead of an error.
    var png = bytesOf(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
                      0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
                      0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
                      0x08, 0x06, 0x00, 0x00, 0x00, 0x5c, 0x72, 0xa8);
    check("a PNG is not sniffed as UTF-16", d(png) === "utf-8");

    var blob = new Uint8Array(200);
    for (var i = 0; i < 200; i++) blob[i] = (i % 3 === 0) ? 0 : (i * 7) % 251;
    check("binary with NULs every third byte stays UTF-8", d(blob) === "utf-8");

    // Non-ASCII log text in UTF-16 still carries NULs from digits, spaces and
    // ASCII field names, which is what the heuristic keys on.
    var de = repeat("Anmeldung fehlgeschlagen f\u00fcr jsmith von 10.4.2.19\r\n", 4);
    var ru = repeat("\u0421\u0431\u043e\u0439 \u0432\u0445\u043e\u0434\u0430 jsmith 10.4.2.19\r\n", 4);
    check("UTF-16 LE German without a BOM is detected",
          d(utf16leBytes(de)) === "utf-16le");
    check("UTF-16 LE Cyrillic without a BOM is detected",
          d(utf16leBytes(ru)) === "utf-16le");

    // ...and multibyte UTF-8 must never be mistaken for UTF-16.
    check("UTF-8 Cyrillic stays UTF-8", d(utf8Bytes(ru)) === "utf-8");
    check("UTF-8 CJK stays UTF-8",
          d(utf8Bytes(repeat("\u767b\u5f55\u5931\u8d25 jsmith 10.4.2.19\n", 4))) === "utf-8");
}

function repeat(s, n) { var o = ""; for (var i = 0; i < n; i++) o += s; return o; }

function utf16leBytes(str) {
    var out = [];
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        out.push(c & 0xff, (c >> 8) & 0xff);
    }
    return new Uint8Array(out);
}

function utf8Bytes(str) {
    var enc = unescape(encodeURIComponent(str)), out = [];
    for (var i = 0; i < enc.length; i++) out.push(enc.charCodeAt(i));
    return new Uint8Array(out);
}

// --- normalization ---------------------------------------------------------
function testNormalize() {
    var n = LogEncoding.normalizeText;
    check("CRLF becomes LF", n("a\r\nb") === "a\nb");
    check("a bare CR becomes LF (old Mac exports)", n("a\rb") === "a\nb");
    check("LF is left alone", n("a\nb") === "a\nb");
    check("a leading BOM character is stripped", n("﻿a\nb") === "a\nb");
    check("a BOM later in the text is left alone",
          n("a﻿b") === "a﻿b");
    check("empty input is safe", n("") === "");
}

// --- full decode (needs TextDecoder; browsers and node have it) ------------
function testDecode() {
    if (typeof TextDecoder === "undefined") {
        print("SKIP - decode tests (no TextDecoder in this runtime)");
        return;
    }
    var r = LogEncoding.decodeLogBytes(asciiAsUtf16(SAMPLE, false, true).buffer);
    check("UTF-16 LE decodes to the original text",
          r.text === SAMPLE.replace(/\r\n/g, "\n"));
    check("...and reports the encoding", r.encoding === "utf-16le");
    check("...and reports that it had CRLF", r.hadCrlf === true);
    check("...leaving no NULs behind (the old 'binary file' bug)",
          r.text.indexOf("\u0000") === -1);

    r = LogEncoding.decodeLogBytes(asciiAsUtf8(SAMPLE, true).buffer);
    check("UTF-8 with BOM decodes without the BOM character",
          r.text.charCodeAt(0) !== 0xfeff);

    r = LogEncoding.decodeLogBytes(asciiAsUtf16(SAMPLE, true, true).buffer);
    check("UTF-16 BE decodes to the original text",
          r.text === SAMPLE.replace(/\r\n/g, "\n"));

    r = LogEncoding.decodeLogBytes(bytesOf(0xff, 0xfe, 0x00, 0x00, 0x41).buffer);
    check("UTF-32 is refused with a message, not mojibake", !!r.error);
}

// --- HTML rendering: the escaping that stands between attacker-influenced log
// --- content and the markup of the page ------------------------------------
//
// Every value below is one an analyst can genuinely end up with: a username
// from a failed logon, an Account Name field, a quoted CSV cell. The masker
// captures them verbatim, and the restored answer puts them back into the page.
function testEscaping() {
    var esc = LogRender.escapeHtml;

    check("escapes &", esc("a & b") === "a &amp; b");
    check("escapes <", esc("<script>").indexOf("<") === -1);
    check("escapes double quotes", esc('a"b') === "a&quot;b");
    check("escapes single quotes", esc("a'b") === "a&#39;b");
    check("leaves ordinary text alone", esc("WS-FIN-07") === "WS-FIN-07");
    check("survives null/undefined", esc(null) === "" && esc(undefined) === "");
}

// A quote that escapes an attribute is an event handler, not a cosmetic bug:
// the page it lands on can read /vault, which holds every real value the tool
// has ever unmasked.
function testAttributeInjection() {
    // As produced by masking `Account Name:  a" onmouseover=alert(1) b`.
    var hostile = 'a" onmouseover=alert(1) b';
    var mapping = { "[USER_1]": hostile };
    var html = LogRender.highlightRestored(
        "The account " + hostile + " failed to log in.", mapping);

    // The raw value carries a double quote; if any of it survives verbatim,
    // that quote closed data-real early and onmouseover became an attribute.
    check("no raw quote from the value survives into the markup",
          html.indexOf(hostile) === -1);
    check("...the quote is entity-encoded instead",
          html.indexOf("&quot; onmouseover=alert(1)") !== -1);
    check("the handler text is inert, not an attribute delimiter",
          html.indexOf('="a" onmouseover') === -1);
    check("the value is still shown to the analyst",
          html.indexOf("onmouseover=alert(1)") !== -1);

    // The same value reaching the masked view's hover card.
    var masked = LogRender.renderMasked("saw [USER_1] here", mapping);
    check("the hover card escapes it too", masked.indexOf('="a"') === -1);
    check("...and still names the alias", masked.indexOf("[USER_1]") !== -1);

    // Single quotes close attributes just as well.
    var sq = { "[HOST_1]": "a' onfocus=alert(1) b" };
    var sqHtml = LogRender.highlightRestored("host a' onfocus=alert(1) b down", sq);
    check("single quotes are escaped as well",
          sqHtml.indexOf("a' onfocus=") === -1);
    check("...and encoded rather than dropped",
          sqHtml.indexOf("a&#39; onfocus=") !== -1);

    // Angle brackets were always handled; check the regression stays covered.
    var tag = { "[USER_2]": "<img src=x onerror=alert(1)>" };
    var tagHtml = LogRender.highlightRestored(
        "user <img src=x onerror=alert(1)> seen", tag);
    check("markup in a restored value is inert",
          tagHtml.indexOf("<img") === -1);
}

// Restoring must not corrupt the surrounding answer.
function testRestoreRoundTrip() {
    var mapping = { "[USER_1]": "jsmith", "[IP_1]": "10.4.2.19" };
    var html = LogRender.highlightRestored(
        "jsmith logged in from 10.4.2.19 twice.", mapping);
    check("both values are badged",
          (html.match(/restored-badge/g) || []).length === 2);
    check("the alias is shown on the card", html.indexOf("[USER_1]") !== -1);
    check("no substitution token leaks into the output",
          html.indexOf("") === -1);
}


testDetection();
testBinaryAndNonAscii();
testNormalize();
testDecode();
testEscaping();
testAttributeInjection();
testRestoreRoundTrip();

if (failures) {
    print("\n" + failures + " frontend check(s) FAILED.");
    if (typeof process !== "undefined") process.exit(1);
    throw new Error("frontend tests failed");
}
print("\nAll frontend tests passed.");
