/*
 * Redeems a magic link.
 *
 * The token arrives in the URL fragment rather than the query string. Browsers never send a
 * fragment to a server, so it stays out of access logs, Referer headers and proxy traces — which
 * is the entire reason the emailed link is shaped that way.
 *
 * In a separate file rather than inline so the page can be served under a Content-Security-Policy
 * that does not need 'unsafe-inline'. That matters more than usual here: this origin also serves
 * the identity service.
 */
(function () {
  "use strict";

  var status = document.getElementById("status");
  var result = document.getElementById("result");
  var tokenBox = document.getElementById("token");

  function fail(message) {
    status.textContent = message;
    status.classList.add("error");
  }

  function readTokenFromFragment() {
    var fragment = window.location.hash.replace(/^#/, "");
    var token = new URLSearchParams(fragment).get("token");

    // Drop it from the address bar immediately, so the credential does not sit in browser history
    // or get shoulder-read from the URL. It is already held in a local variable.
    if (token) {
      history.replaceState(null, "", window.location.pathname);
    }
    return token;
  }

  var token = readTokenFromFragment();

  if (!token) {
    fail("This link is missing its token. Request a new sign-in link.");
    return;
  }

  fetch("../auth/magic-link/redeem", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: token }),
  })
    .then(function (response) {
      if (response.ok) {
        return response.json();
      }
      // The server answers 401 identically for unknown, already-used and expired links, so this
      // message must not guess between them either.
      throw new Error("This link is no longer valid. It may already have been used, or it may have expired.");
    })
    .then(function (body) {
      status.textContent = "Signed in.";
      tokenBox.value = body.access_token;
      result.hidden = false;
    })
    .catch(function (error) {
      fail(error.message);
    });

  document.getElementById("copy").addEventListener("click", function () {
    tokenBox.select();
    navigator.clipboard.writeText(tokenBox.value);
  });
})();
