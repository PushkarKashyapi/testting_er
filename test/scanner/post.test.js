import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test, expect } from "@jest/globals";

const scannerDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scannerDir, "../..");
const configDir = path.join(root, "test");

function readJson(file) {
  return JSON.parse(fs.readFileSync(path.join(configDir, file), "utf8"));
}

const config = readJson("config.json");
const postConfig = readJson("post.json");

if (!config.targetUrl) {
  throw new Error("config.json must define targetUrl.");
}

const base = new URL(config.targetUrl);
const timeoutMs = config.timeoutMs ?? 8000;

if (!["http:", "https:"].includes(base.protocol)) {
  throw new Error("targetUrl must use HTTP or HTTPS.");
}

if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
  throw new Error("timeoutMs must be a positive number.");
}

if (postConfig.method !== "POST") {
  throw new Error('post.json must declare "method": "POST".');
}

if (!Array.isArray(postConfig.endpoints)) {
  throw new Error("post.json must contain an endpoints array.");
}

function validateEndpoint(endpoint) {
  if (
    typeof endpoint.path !== "string" ||
    !endpoint.path.startsWith("/") ||
    endpoint.path.startsWith("//")
  ) {
    throw new Error(`Invalid POST endpoint: ${endpoint.path}`);
  }

  const url = new URL(endpoint.path, base);

  if (url.origin !== base.origin) {
    throw new Error(`Endpoint escapes target origin: ${endpoint.path}`);
  }

  return url;
}

for (const endpoint of postConfig.endpoints) {
  validateEndpoint(endpoint);
}

const stackPattern =
  /(at\s+.+:\d+:\d+|node_modules\/|SequelizeDatabaseError|MongoServerError|Traceback \(most recent call last\))/i;

const defaultPayloads = [
  "' OR '1'='1",
  "<script>alert(1)</script>",
  "../../etc/passwd",
  "${7*7}",
];

function isEnabled(endpoint, name) {
  if (
    endpoint.tests &&
    Object.prototype.hasOwnProperty.call(endpoint.tests, name)
  ) {
    return endpoint.tests[name] === true;
  }

  return postConfig.defaultTests?.[name] === true;
}

function safeToModify(endpoint) {
  return (
    config.security?.allowDestructiveTests === true &&
    endpoint.testRequest?.enabled === true
  );
}

function requireSafeRequest(endpoint, testName) {
  if (!safeToModify(endpoint)) {
    throw new Error(
      `${testName} requires security.allowDestructiveTests=true ` +
        `and endpoint.testRequest.enabled=true. Use an authorized test environment.`,
    );
  }
}

function requireTestRequest(endpoint) {
  requireSafeRequest(endpoint, "POST test");

  const body = endpoint.testRequest.body;

  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new Error(
      `POST ${endpoint.path} requires a JSON object in testRequest.body.`,
    );
  }

  return body;
}

async function sendPost(endpoint, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const headers = {
      "user-agent": "VibeShield/0.1 authorized-security-test",
      accept: "*/*",
      ...(options.body !== undefined
        ? { "content-type": "application/json" }
        : {}),
      ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
      ...(options.headers ?? {}),
    };

    return await fetch(validateEndpoint(endpoint), {
      method: "POST",
      redirect: "manual",
      signal: controller.signal,
      headers,
      ...(options.body !== undefined
        ? { body: JSON.stringify(options.body) }
        : {}),
    });
  } finally {
    clearTimeout(timer);
  }
}

async function inspectResponse(response) {
  return {
    status: response.status,
    headers: response.headers,
    body: await response.text(),
  };
}

function enabledEndpoints(name) {
  return postConfig.endpoints.filter((endpoint) => isEnabled(endpoint, name));
}

describe("VibeShield configured POST endpoints", () => {
  test("validates POST scanner configuration", () => {
    expect(postConfig.method).toBe("POST");
    expect(Array.isArray(postConfig.endpoints)).toBe(true);
    expect(base.origin).toBeTruthy();
  });

  for (const endpoint of postConfig.endpoints) {
    describe(`POST ${endpoint.path}`, () => {
      // POST may create or modify data. Keep these tests skipped
      // unless the endpoint and global configuration opt in.
      const safe = safeToModify(endpoint);

      // 1. Availability
      if (safe) {
        test("handles the configured request without a server error", async () => {
          const body = requireTestRequest(endpoint);
          const response = await sendPost(endpoint, { body });

          expect(response.status).toBeLessThan(500);
        });
      } else {
        test.skip("availability request skipped: destructive testing is not enabled", () => {});
      }

      // 2. Authentication
      if (isEnabled(endpoint, "authentication") && safe) {
        test("enforces configured public/protected behavior", async () => {
          if (!["public", "protected"].includes(endpoint.authMode)) {
            throw new Error(
              `Set authMode to "public" or "protected" for ${endpoint.path}.`,
            );
          }

          const body = requireTestRequest(endpoint);
          const response = await sendPost(endpoint, { body });
          const denied = [401, 403].includes(response.status);

          if (endpoint.authMode === "protected") {
            expect(denied).toBe(true);
          } else {
            expect(denied).toBe(false);
          }
        });
      } else {
        test.skip("authentication check disabled or unsafe to execute", () => {});
      }

      // 3. Security misconfiguration
      if (isEnabled(endpoint, "securityMisconfiguration") && safe) {
        test("checks security response headers", async () => {
          const body = requireTestRequest(endpoint);
          const response = await sendPost(endpoint, { body });

          await response.arrayBuffer();

          expect(response.headers.get("x-powered-by")).toBeNull();
          expect(
            response.headers.get("x-content-type-options")?.toLowerCase(),
          ).toBe("nosniff");
        });
      } else {
        test.skip("security-header check disabled or unsafe to execute", () => {});
      }

      // 4. Injection probes
      const injection = endpoint.injectionTest;
      const injectionEnabled =
        isEnabled(endpoint, "injection") &&
        injection?.enabled === true &&
        Array.isArray(injection.fields) &&
        injection.fields.length > 0 &&
        Array.isArray(injection.payloads ?? defaultPayloads);

      if (injectionEnabled && safe) {
        test("checks configured JSON injection probes", async () => {
          const originalBody = requireTestRequest(endpoint);
          const payloads = injection.payloads ?? defaultPayloads;

          for (const field of injection.fields) {
            if (!Object.prototype.hasOwnProperty.call(originalBody, field)) {
              throw new Error(
                `Injection field "${field}" is missing from testRequest.body.`,
              );
            }

            for (const payload of payloads) {
              const body = structuredClone(originalBody);
              body[field] = payload;

              const response = await sendPost(endpoint, { body });
              const result = await inspectResponse(response);

              expect(
                result.status,
                `HTTP ${result.status} for field ${field}`,
              ).toBeLessThan(500);

              expect(
                stackPattern.test(result.body),
                `Possible stack-trace disclosure for field ${field}`,
              ).toBe(false);

              const isHtml = /text\/html/i.test(
                result.headers.get("content-type") ?? "",
              );

              if (isHtml && /<script>alert\(1\)<\/script>/i.test(result.body)) {
                throw new Error(
                  `Possible reflected XSS at ${endpoint.path}, field ${field}.`,
                );
              }
            }
          }
        });
      } else {
        test.skip("injection checks disabled, unconfigured, or unsafe to execute", () => {});
      }

      // 5. Exception handling
      if (isEnabled(endpoint, "exceptionHandling") && safe) {
        test("normal response does not expose obvious stack traces", async () => {
          const body = requireTestRequest(endpoint);
          const response = await sendPost(endpoint, { body });
          const result = await inspectResponse(response);

          expect(stackPattern.test(result.body)).toBe(false);
        });
      } else {
        test.skip("exception-handling check disabled or unsafe to execute", () => {});
      }

      // 6. Logging
      if (isEnabled(endpoint, "logging")) {
        test.todo(
          `Verify POST ${endpoint.path} audit logging with application log integration`,
        );
      } else {
        test.skip("logging checks disabled", () => {});
      }
    });
  }

  // 7. Separate access-control tests
  describe("POST access control", () => {
    const access = postConfig.accessControl;
    const endpoints = access?.enabled ? access.endpoints : [];

    if (!access?.enabled) {
      test.skip("access-control checks disabled", () => {});
    } else if (!Array.isArray(endpoints) || endpoints.length === 0) {
      test("requires configured access-control endpoints", () => {
        throw new Error(
          "Access control is enabled but accessControl.endpoints is empty.",
        );
      });
    } else {
      for (const endpoint of endpoints) {
        validateEndpoint(endpoint);

        if (!safeToModify(endpoint)) {
          test.skip(`${endpoint.path}: access-control test requires destructive-test opt-in`, () => {});
          continue;
        }

        test(`${endpoint.path} enforces configured permissions`, async () => {
          const body = requireTestRequest(endpoint);

          const authorizedEnv =
            access.authorizedTokenEnv ?? "VIBESHIELD_ADMIN_TOKEN";

          const unauthorizedEnv =
            access.unauthorizedTokenEnv ?? "VIBESHIELD_USER_TOKEN";

          const authorizedToken = process.env[authorizedEnv];
          const unauthorizedToken = process.env[unauthorizedEnv];

          if (!authorizedToken || !unauthorizedToken) {
            throw new Error(`Set ${authorizedEnv} and ${unauthorizedEnv}.`);
          }

          const [authorizedResponse, unauthorizedResponse] = await Promise.all([
            sendPost(endpoint, {
              body,
              token: authorizedToken,
            }),
            sendPost(endpoint, {
              body,
              token: unauthorizedToken,
            }),
          ]);

          expect(
            endpoint.expectedAuthorizedStatus ?? [200, 201, 204],
          ).toContain(authorizedResponse.status);

          expect(endpoint.expectedUnauthorizedStatus ?? [401, 403]).toContain(
            unauthorizedResponse.status,
          );
        });
      }
    }
  });

  // 8. Separate cryptographic hashing checks
  describe("POST cryptographic hashing", () => {
    const hashing = postConfig.cryptographicHashing;
    const endpoints = hashing?.enabled ? hashing.endpoints : [];

    if (!hashing?.enabled) {
      test.skip("cryptographic hashing checks disabled", () => {});
    } else if (!Array.isArray(endpoints) || endpoints.length === 0) {
      test("requires configured hashing endpoints", () => {
        throw new Error(
          "Cryptographic hashing is enabled but no endpoints are configured.",
        );
      });
    } else {
      for (const endpoint of endpoints) {
        test.skip(`${endpoint.path}: hashing verification requires source, database, or test instrumentation`, () => {});
      }
    }
  });
});
