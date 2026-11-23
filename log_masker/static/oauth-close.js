// Closes the OAuth callback tab a moment after sign-in resolves. External
// rather than inline so the page needs no script-src exception (see the CSP in
// app.py); the tab was opened by the sign-in redirect, so window.close() is
// allowed to close it.
setTimeout(function () { window.close(); }, 2500);
