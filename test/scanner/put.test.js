import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test, expect } from "@jest/globals";

const scannerDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scannerDir, "../..");
const vibeShieldDir = path.join(root, "test");

function readJson(file) {
  return JSON.parse(fs.readFileSync(path.join(vibeShieldDir, file), "utf8"));
}

const config = readJson("config.json");
const putConfig = readJson("put.json");

if (!config.targetUrl) {
  throw new Error("config.json must define targetUrl.");
}

const base = new URL(config.targetUrl);
const timeoutMs = config.timeoutMs ?? 8000;

if (!["http:", "https:"].includes(base.protocol)) {
  throw new Error("targetUrl must use HTTP or HTTPS.");
}

if (putConfig.method !== "PUT") {
  throw new Error('put.json must declare "method": "PUT".');
}

if (!Array.isArray(putConfig.endpoints)) {
  throw new Error("put.json must contain an endpoints array.");
}

if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
  throw new Error("config.timeoutMs must be a positive number.");
}

function validateEndpoint(endpoint) {
  if (
    !endpoint ||
    typeof endpoint.path !== "string" ||
    !endpoint.path.startsWith("/") ||
    endpoint.path.startsWith("//")
  ) {
    throw new Error(`Invalid PUT endpoint: ${endpoint?.path}`);
  }

  const url = new URL(endpoint.path, base);

  if (url.origin !== base.origin) {
    throw new Error(`Endpoint escapes target origin: ${endpoint.path}`);
  }

  return url;
}

for (const endpoint of putConfig.endpoints) {
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
  const setting = endpoint.tests?.[name];

  if (setting !== undefined) {
    return setting === true || setting?.enabled === true;
  }

  const defaultSetting = putConfig.defaultTests?.[name];
  return defaultSetting === true || defaultSetting?.enabled === true;
}

function requireTestRequest(endpoint) {
  if (endpoint.testRequest?.enabled !== true) {
    throw new Error(`PUT ${endpoint.path} requires testRequest.enabled=true`);
  }

  const body = endpoint.testRequest.body;

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error(
      `PUT ${endpoint.path} requires a JSON object in testRequest.body`,
    );
  }

  return body;
}

function safeToModify(endpoint) {
  return (
    config.security?.allowDestructiveTests === true &&
    endpoint.testRequest?.enabled === true &&
    endpoint.testRequest.body !== undefined
  );
}

function skipUnless(condition, name, callback) {
  if (condition) {
    test(name, callback);
  } else {
    test.skip(name, () => {});
  }
}

async function sendPut(endpoint, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(validateEndpoint(endpoint), {
      method: "PUT",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "user-agent": "VibeShield/0.1 authorized-security-test",
        ...(options.body !== undefined
          ? { "content-type": "application/json" }
          : {}),
        ...(options.headers ?? {}),
      },
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

describe("VibeShield configured PUT endpoints", () => {
  for (const endpoint of putConfig.endpoints) {
    describe(`PUT ${endpoint.path}`, () => {
      const approved = safeToModify(endpoint);

      // 1. Availability / response handling
      skipUnless(
        approved,
        "handles the configured PUT request without a server error",
        async () => {
          const response = await sendPut(endpoint, {
            body: requireTestRequest(endpoint),
          });

          expect(response.status).toBeLessThan(500);
          await response.text();
        },
      );

      // 2. Authentication
      // Anonymous PUT can still modify data on a public endpoint,
      // so this check also requires explicit destructive-test approval.
      skipUnless(
        approved && isEnabled(endpoint, "authentication"),
        "enforces configured public/protected behavior",
        async () => {
          if (!["public", "protected"].includes(endpoint.authMode)) {
            throw new Error(
              `Set authMode to "public" or "protected" for ${endpoint.path}.`,
            );
          }

          const response = await sendPut(endpoint, {
            body: requireTestRequest(endpoint),
          });

          await response.text();

          const denied = [401, 403].includes(response.status);

          if (endpoint.authMode === "protected") {
            expect(denied).toBe(true);
          } else {
            expect(denied).toBe(false);
          }
        },
      );

      // 3. Security response headers
      skipUnless(
        approved && isEnabled(endpoint, "securityMisconfiguration"),
        "checks security response headers",
        async () => {
          const response = await sendPut(endpoint, {
            body: requireTestRequest(endpoint),
          });

          await response.text();

          expect(response.headers.get("x-powered-by")).toBeNull();
          expect(
            response.headers.get("x-content-type-options")?.toLowerCase(),
          ).toBe("nosniff");
        },
      );

      // 4. Injection probes
      const injection = endpoint.injectionTest;

      skipUnless(
        approved &&
          isEnabled(endpoint, "injection") &&
          injection?.enabled === true &&
          Array.isArray(injection.fields) &&
          injection.fields.length > 0,
        "checks configured JSON fields for injection symptoms",
        async () => {
          const originalBody = requireTestRequest(endpoint);
          const payloads = injection.payloads ?? defaultPayloads;

          if (
            !Array.isArray(payloads) ||
            payloads.some((payload) => typeof payload !== "string")
          ) {
            throw new Error(
              "injectionTest.payloads must be an array of strings.",
            );
          }

          for (const field of injection.fields) {
            if (
              typeof field !== "string" ||
              !Object.hasOwn(originalBody, field)
            ) {
              throw new Error(
                `Injection field "${field}" must exist in testRequest.body.`,
              );
            }

            for (const payload of payloads) {
              const body = structuredClone(originalBody);
              body[field] = payload;

              const response = await sendPut(endpoint, { body });
              const result = await inspectResponse(response);

              expect(
                result.status,
                `Unexpected server error for field "${field}"`,
              ).toBeLessThan(500);

              expect(
                stackPattern.test(result.body),
                `Possible stack-trace disclosure for field "${field}"`,
              ).toBe(false);

              const contentType = result.headers.get("content-type") ?? "";
              const isHtml = /text\/html/i.test(contentType);

              if (
                isHtml &&
                /<script>alert\s*\(\s*1\s*\)<\/script>/i.test(result.body)
              ) {
                throw new Error(
                  `Possible reflected XSS at ${endpoint.path}, field "${field}".`,
                );
              }
            }
          }
        },
      );

      // 5. Exception handling
      skipUnless(
        approved && isEnabled(endpoint, "exceptionHandling"),
        "normal response does not expose recognizable stack traces",
        async () => {
          const response = await sendPut(endpoint, {
            body: requireTestRequest(endpoint),
          });

          const result = await inspectResponse(response);
          expect(stackPattern.test(result.body)).toBe(false);
        },
      );

      // 6. Logging
      if (isEnabled(endpoint, "logging")) {
        test.skip("logging verification requires captured application logs or a logging integration", () => {});
      } else {
        test.skip("logging checks disabled", () => {});
      }
    });
  }

  // 7. Separate access-control checks
  describe("PUT access control", () => {
    const access = putConfig.accessControl;
    const endpoints = access?.enabled === true ? (access.endpoints ?? []) : [];

    if (access?.enabled !== true) {
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

        const approved = safeToModify(endpoint);

        skipUnless(
          approved,
          `${endpoint.path}: requires an explicitly approved test request`,
          async () => {},
        );

        if (!approved) continue;

        test(`${endpoint.path} enforces configured permissions`, async () => {
          const adminEnv =
            access.authorizedTokenEnv ?? "VIBESHIELD_ADMIN_TOKEN";
          const userEnv =
            access.unauthorizedTokenEnv ?? "VIBESHIELD_USER_TOKEN";

          const adminToken = process.env[adminEnv];
          const userToken = process.env[userEnv];

          if (!adminToken || !userToken) {
            throw new Error(`Set both ${adminEnv} and ${userEnv}.`);
          }

          if (adminToken === userToken) {
            throw new Error(
              "Access-control testing requires distinct admin and user tokens.",
            );
          }

          const body = requireTestRequest(endpoint);

          // Sequential requests avoid simultaneous writes to the same resource.
          // Use a disposable test environment and a safe, repeatable test body.
          const adminResponse = await sendPut(endpoint, {
            body,
            headers: { Authorization: `Bearer ${adminToken}` },
          });
          await adminResponse.text();

          const userResponse = await sendPut(endpoint, {
            body,
            headers: { Authorization: `Bearer ${userToken}` },
          });
          await userResponse.text();

          expect(endpoint.expectedAuthorizedStatus ?? [200, 204]).toContain(
            adminResponse.status,
          );

          expect(endpoint.expectedUnauthorizedStatus ?? [401, 403]).toContain(
            userResponse.status,
          );
        });
      }
    }
  });

  // 8. Cryptographic hashing
  describe("PUT cryptographic hashing", () => {
    const hashing = putConfig.cryptographicHashing;
    const endpoints =
      hashing?.enabled === true ? (hashing.endpoints ?? []) : [];

    if (hashing?.enabled !== true) {
      test.skip("cryptographic hashing checks disabled", () => {});
    } else if (!Array.isArray(endpoints) || endpoints.length === 0) {
      test("requires configured hashing endpoints", () => {
        throw new Error(
          "Cryptographic hashing is enabled but no endpoints are configured.",
        );
      });
    } else {
      for (const endpoint of endpoints) {
        validateEndpoint(endpoint);

        test.skip(`${endpoint.path}: hashing verification requires source, database, or test instrumentation`, () => {});
      }
    }
  });
});
