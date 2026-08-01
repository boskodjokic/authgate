/*
 * AuthGate admin console.
 *
 * Deliberately plain: no framework, no build step, served from the jar. The interesting decisions
 * are about where the token lives rather than about the rendering.
 *
 * The access token is held in a module-local variable and nowhere else — not localStorage, not
 * sessionStorage, not a cookie. A cookie would reintroduce CSRF, which the service is currently
 * free of precisely because it has no ambient credential; storage would leave the token readable
 * by any script that ever manages to run on this origin, which also serves the identity service.
 * The cost is that a page reload signs you out, and on a console whose sign-in is one emailed link
 * that is a fair trade.
 */
(function () {
  "use strict";

  var accessToken = null;
  var refreshToken = null;
  var identity = null;
  var currentTenant = null;

  var el = function (id) {
    return document.getElementById(id);
  };

  function show(section) {
    el("signin").hidden = section !== "signin";
    el("app").hidden = section !== "app";
  }

  function fail(message) {
    var box = el("error");
    box.textContent = message;
    box.hidden = false;
  }

  function clearError() {
    el("error").hidden = true;
  }

  /* -- API ------------------------------------------------------------- */

  function api(method, path, body) {
    return fetch(".." + path, {
      method: method,
      headers: Object.assign(
        { "content-type": "application/json" },
        accessToken ? { authorization: "Bearer " + accessToken } : {}
      ),
      body: body === undefined ? undefined : JSON.stringify(body),
    }).then(function (response) {
      if (response.status === 401) {
        // Either the token expired or it was revoked. Both mean the same thing to a console with
        // no stored credential: start again.
        signOut();
        throw new Error("Your session has ended. Sign in again.");
      }
      if (response.status === 403) {
        throw new Error("You do not have permission to do that.");
      }
      if (!response.ok) {
        return response
          .json()
          .catch(function () {
            return {};
          })
          .then(function (problem) {
            throw new Error(problem.detail || problem.error || "Request failed (" + response.status + ")");
          });
      }
      return response.status === 204 ? null : response.json();
    });
  }

  /* -- sign in --------------------------------------------------------- */

  function readTokenFromFragment() {
    var token = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("token");
    if (token) {
      // Out of the address bar at once, so the credential is not left in browser history.
      history.replaceState(null, "", window.location.pathname);
    }
    return token;
  }

  /*
   * A JWT payload is base64url, which atob does not accept: it rejects the '-' and '_' that stand
   * in for '+' and '/'. Whether a given token trips it depends on the bytes, so this fails
   * intermittently rather than always — worse than failing outright.
   *
   * Read for display only. Nothing here is trusted: the server verifies the signature on every
   * request, and this side just wants an address to put in the header.
   */
  function readClaims(jwt) {
    var payload = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(payload.padEnd(payload.length + ((4 - (payload.length % 4)) % 4), "=")));
  }

  function adopt(session) {
    accessToken = session.access_token;
    refreshToken = session.refresh_token;
    identity = readClaims(session.access_token);
    el("whoami").textContent = identity.email;
    show("app");
    return loadAll();
  }

  function signOut() {
    var hadToken = accessToken;
    var body = refreshToken ? { refresh_token: refreshToken } : {};
    if (hadToken) {
      // Best effort: tell the server to withdraw the family and denylist this access token. The
      // local state is cleared either way.
      fetch("../auth/logout", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer " + hadToken },
        body: JSON.stringify(body),
      }).catch(function () {});
    }
    accessToken = null;
    refreshToken = null;
    identity = null;
    currentTenant = null;
    show("signin");
  }

  el("signin-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var status = el("signin-status");
    var form = new FormData(event.target);

    fetch("../auth/magic-link", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenant: form.get("tenant"), email: form.get("email") }),
    })
      .then(function () {
        // Always the same message. The server answers 202 whether or not the address matches an
        // account, and the console must not undo that by saying something different.
        status.textContent = "If that address has an account, a sign-in link is on its way.";
        status.hidden = false;
      })
      .catch(function () {
        status.textContent = "Could not reach the server.";
        status.hidden = false;
      });
  });

  el("signout").addEventListener("click", signOut);

  /* -- rendering ------------------------------------------------------- */

  function table(node, columns, rows, empty) {
    if (!rows.length) {
      node.innerHTML = '<tr><td class="muted">' + empty + "</td></tr>";
      return;
    }
    var head = "<tr>" + columns.map(function (c) { return "<th>" + c.label + "</th>"; }).join("") + "</tr>";
    var body = rows
      .map(function (row) {
        return (
          "<tr>" +
          columns
            .map(function (c) {
              // textContent-equivalent escaping: every value below is operator-supplied, and this
              // origin also serves the identity service, so an injected script here would be a
              // compromise of identity rather than a defacement.
              var cell = document.createElement("td");
              cell.textContent = c.value(row);
              return cell.outerHTML;
            })
            .join("") +
          "</tr>"
        );
      })
      .join("");
    node.innerHTML = head + body;
  }

  function loadAll() {
    clearError();
    return api("GET", "/admin/tenants")
      .then(function (tenants) {
        table(
          el("tenants"),
          [
            { label: "Slug", value: function (t) { return t.slug; } },
            { label: "Name", value: function (t) { return t.name; } },
            { label: "Active", value: function (t) { return t.active ? "yes" : "no"; } },
          ],
          tenants,
          "No tenants yet."
        );
        currentTenant = currentTenant || (tenants[0] && tenants[0].slug);
        el("scope").textContent = currentTenant ? "in " + currentTenant : "";
        return currentTenant ? loadTenantDetail(currentTenant) : null;
      })
      .catch(function (error) {
        fail(error.message);
      });
  }

  function loadTenantDetail(slug) {
    return Promise.all([
      api("GET", "/admin/tenants/" + encodeURIComponent(slug) + "/accounts"),
      api("GET", "/admin/tenants/" + encodeURIComponent(slug) + "/roles"),
    ]).then(function (results) {
      table(
        el("accounts"),
        [
          { label: "Email", value: function (a) { return a.email; } },
          { label: "Name", value: function (a) { return a.displayName || ""; } },
          { label: "Roles", value: function (a) { return a.roles.join(", ") || "—"; } },
          { label: "Superuser", value: function (a) { return a.superuser ? "yes" : ""; } },
        ],
        results[0],
        "No accounts in this tenant."
      );
      table(
        el("roles"),
        [
          { label: "Role", value: function (r) { return r.name; } },
          {
            label: "Permissions",
            value: function (r) {
              return Object.keys(r.permissions)
                .map(function (resource) { return resource + ":" + r.permissions[resource].join("/"); })
                .join("  ");
            },
          },
        ],
        results[1],
        "No roles in this tenant."
      );
    });
  }

  /* -- mutations ------------------------------------------------------- */

  el("tenant-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var form = new FormData(event.target);
    api("POST", "/admin/tenants", { slug: form.get("slug"), name: form.get("name") })
      .then(function () {
        event.target.reset();
        return loadAll();
      })
      .catch(function (error) { fail(error.message); });
  });

  el("account-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var form = new FormData(event.target);
    api("POST", "/admin/tenants/" + encodeURIComponent(currentTenant) + "/accounts", {
      email: form.get("email"),
      displayName: form.get("displayName"),
    })
      .then(function () {
        event.target.reset();
        return loadTenantDetail(currentTenant);
      })
      .catch(function (error) { fail(error.message); });
  });

  el("role-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var form = new FormData(event.target);
    var permissions = form
      .get("permissions")
      .split(",")
      .map(function (entry) { return entry.trim(); })
      .filter(Boolean)
      .map(function (entry) {
        var parts = entry.split(":");
        return { resource: parts[0], action: parts[1] };
      });

    api(
      "PUT",
      "/admin/tenants/" + encodeURIComponent(currentTenant) + "/roles/" + encodeURIComponent(form.get("name")),
      { permissions: permissions }
    )
      .then(function () {
        event.target.reset();
        return loadTenantDetail(currentTenant);
      })
      .catch(function (error) { fail(error.message); });
  });

  /* -- start ----------------------------------------------------------- */

  var handoff = readTokenFromFragment();
  if (handoff) {
    fetch("../auth/magic-link/redeem", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: handoff }),
    })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("link no longer valid");
        }
        return response.json();
      })
      .then(adopt)
      .catch(function () {
        show("signin");
        var status = el("signin-status");
        status.textContent = "That link is no longer valid. Request another.";
        status.hidden = false;
      });
  } else {
    show("signin");
  }
})();
