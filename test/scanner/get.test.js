import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test, expect, beforeAll } from "@jest/globals";

const scannerDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scannerDir, "../..");
const configDir = path.join(root, "test");

function readJson(file) {
  return JSON.parse(fs.readFileSync(path.join(configDir, file), "utf8"));
}

const config = readJson("config.json");
const getConfig = readJson("get.json");

if (!config.targetUrl) {
  throw new Error("test/config.json must define targetUrl.");
}

const base = new URL(config.targetUrl);
const timeoutMs = config.timeoutMs ?? 8000;

if (!["http:", "https:"].includes(base.protocol)) {
  throw new Error("targetUrl must use HTTP or HTTPS.");
}

if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
  throw new Error("timeoutMs must be a positive number.");
}

if (getConfig.method !== "GET") {
  throw new Error('test/get.json must declare "method": "GET".');
}

if (!Array.isArray(getConfig.endpoints)) {
  throw new Error("test/get.json must contain an endpoints array.");
}

function validateEndpoint(endpoint) {
  if (
    !endpoint ||
    typeof endpoint.path !== "string" ||
    !endpoint.path.startsWith("/") ||
    endpoint.path.startsWith("//")
  ) {
    throw new Error(`Invalid GET endpoint: ${endpoint?.path}`);
  }

  const url = new URL(endpoint.path, base);

  if (url.origin !== base.origin) {
    throw new Error(`Endpoint escapes target origin: ${endpoint.path}`);
  }

  return url;
}

for (const endpoint of getConfig.endpoints) {
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

const queryParameterNames = getConfig.probes?.queryParameterNames ?? [
  "q",
  "search",
  "id",
  "name",
  "input",
];

const payloads = getConfig.probes?.payloads ?? defaultPayloads;

function isEnabled(endpoint, name) {
  const aliases = {
    authentication: ["authentication", "authenticationFailures"],
    securityMisconfiguration: ["securityMisconfiguration"],
    injection: ["injection"],
    exceptionHandling: ["exceptionHandling"],
  };

  const names = aliases[name] ?? [name];

  for (const key of names) {
    if (
      endpoint.tests &&
      Object.prototype.hasOwnProperty.call(endpoint.tests, key)
    ) {
      return endpoint.tests[key] === true;
    }
  }

  for (const key of names) {
    if (
      getConfig.defaultTests &&
      Object.prototype.hasOwnProperty.call(getConfig.defaultTests, key)
    ) {
      return getConfig.defaultTests[key] === true;
    }
  }

  return false;
}

async function sendGet(url, headers = {}) {
  const controller = new AbortController();

  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "user-agent": "VibeShield/0.1 authorized-security-test",
        accept: "*/*",
        ...headers,
      },
    });
  } catch (error) {
    if (error?.cause?.code === "ECONNREFUSED") {
      throw new Error(
        `Cannot connect to ${base.origin}. ` +
          "Start the API server before running the tests.",
        { cause: error },
      );
    }

    if (error?.name === "AbortError") {
      throw new Error(`GET ${url.pathname} timed out after ${timeoutMs} ms.`, {
        cause: error,
      });
    }

    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function readResponse(response) {
  return {
    status: response.status,
    headers: response.headers,
    body: await response.text(),
  };
}

beforeAll(async () => {
  try {
    const response = await fetch(base, {
      method: "GET",
      signal: AbortSignal.timeout(Math.min(timeoutMs, 3000)),
    });

    await response.body?.cancel();
  } catch (error) {
    throw new Error(
      `GET scanner cannot reach ${base.origin}. ` +
        "Start the API using 'node server.js', then run " +
        "'npm test' in a second terminal. " +
        `Original error: ${error.message}`,
    );
  }
});

describe("VibeShield configured GET endpoints", () => {
  for (const endpoint of getConfig.endpoints) {
    describe(`GET ${endpoint.path}`, () => {
      test("does not return a server error", async () => {
        const response = await sendGet(validateEndpoint(endpoint));

        await response.text();

        expect(response.status).toBeLessThan(500);
      });

      if (isEnabled(endpoint, "authentication")) {
        test("enforces configured public/protected behavior", async () => {
          if (!["public", "protected"].includes(endpoint.authMode)) {
            throw new Error(
              `Set authMode to "public" or "protected" ` +
                `for ${endpoint.path}.`,
            );
          }

          const response = await sendGet(validateEndpoint(endpoint));

          await response.text();

          const denied = [401, 403].includes(response.status);

          if (endpoint.authMode === "protected") {
            expect(denied).toBe(true);
          } else {
            expect(denied).toBe(false);
          }
        });
      } else {
        test.skip("authentication check disabled", () => {});
      }

      if (isEnabled(endpoint, "securityMisconfiguration")) {
        test("checks security response headers", async () => {
          const response = await sendGet(validateEndpoint(endpoint));

          await response.text();

          expect(response.headers.get("x-powered-by")).toBeNull();

          expect(
            response.headers.get("x-content-type-options")?.toLowerCase(),
          ).toBe("nosniff");
        });
      } else {
        test.skip("security misconfiguration check disabled", () => {});
      }

      if (isEnabled(endpoint, "injection")) {
        test("handles query probes without server errors or obvious disclosures", async () => {
          for (const parameter of queryParameterNames) {
            for (const payload of payloads) {
              const url = validateEndpoint(endpoint);

              url.searchParams.set(parameter, payload);

              const response = await sendGet(url);
              const result = await readResponse(response);

              if (result.status >= 500) {
                throw new Error(
                  `Server error: HTTP ${result.status} for parameter "${parameter}" at ${endpoint.path}`,
                );
              }

              expect(result.status).toBeLessThan(500);

              if (stackPattern.test(result.body)) {
                throw new Error(
                  `Possible stack-trace disclosure for ${parameter} at ${endpoint.path}`,
                );
              }

              expect(stackPattern.test(result.body)).toBe(false);

              const isHtml = /text\/html/i.test(
                result.headers.get("content-type") ?? "",
              );

              if (
                isHtml &&
                /<script>alert\s*\(\s*1\s*\)<\/script>/i.test(result.body)
              ) {
                throw new Error(
                  `Possible reflected XSS at ${endpoint.path}, ` +
                    `parameter ${parameter}`,
                );
              }
            }
          }
        });
      } else {
        test.skip("injection checks disabled", () => {});
      }

      if (isEnabled(endpoint, "exceptionHandling")) {
        test("normal response does not expose obvious stack traces", async () => {
          const response = await sendGet(validateEndpoint(endpoint));

          const result = await readResponse(response);

          expect(stackPattern.test(result.body)).toBe(false);
        });
      } else {
        test.skip("exception handling check disabled", () => {});
      }
    });
  }

  describe("GET access control", () => {
    const accessControl = getConfig.accessControl;

    const accessEndpoints =
      accessControl?.enabled === true ? (accessControl.endpoints ?? []) : [];

    if (accessControl?.enabled !== true) {
      test.skip("access-control tests disabled", () => {});
    } else if (
      !Array.isArray(accessEndpoints) ||
      accessEndpoints.length === 0
    ) {
      test("requires configured access-control endpoints", () => {
        throw new Error(
          "Access control is enabled but " +
            "accessControl.endpoints is empty.",
        );
      });
    } else {
      const authorizedTokenEnv =
        accessControl.authorizedTokenEnv ??
        config.authentication?.adminTokenEnv ??
        "VIBESHIELD_ADMIN_TOKEN";

      const unauthorizedTokenEnv =
        accessControl.unauthorizedTokenEnv ??
        config.authentication?.userTokenEnv ??
        "VIBESHIELD_USER_TOKEN";

      for (const endpoint of accessEndpoints) {
        validateEndpoint(endpoint);

        test(`access control: GET ${endpoint.path}`, async () => {
          const authorizedToken = process.env[authorizedTokenEnv];

          const unauthorizedToken = process.env[unauthorizedTokenEnv];

          if (!authorizedToken || !unauthorizedToken) {
            throw new Error(
              `Set ${authorizedTokenEnv} and ` +
                `${unauthorizedTokenEnv} environment variables.`,
            );
          }

          if (authorizedToken === unauthorizedToken) {
            throw new Error(
              "Authorized and unauthorized tokens " + "must be different.",
            );
          }

          const [authorizedResponse, unauthorizedResponse] = await Promise.all([
            sendGet(validateEndpoint(endpoint), {
              Authorization: `Bearer ${authorizedToken}`,
            }),
            sendGet(validateEndpoint(endpoint), {
              Authorization: `Bearer ${unauthorizedToken}`,
            }),
          ]);

          await Promise.all([
            authorizedResponse.text(),
            unauthorizedResponse.text(),
          ]);

          const expectedAuthorized = endpoint.expectedAuthorizedStatus ?? [200];

          const expectedUnauthorized = endpoint.expectedUnauthorizedStatus ?? [
            401, 403,
          ];

          expect(expectedAuthorized).toContain(authorizedResponse.status);

          expect(expectedUnauthorized).toContain(unauthorizedResponse.status);
        });
      }
    }
  });
});
