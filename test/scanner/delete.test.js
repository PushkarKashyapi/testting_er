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
const deleteConfig = readJson("delete.json");

if (!config.targetUrl) {
  throw new Error("config.json must define targetUrl.");
}

const base = new URL(config.targetUrl);
const timeoutMs = config.timeoutMs ?? 8000;

if (!["http:", "https:"].includes(base.protocol)) {
  throw new Error("targetUrl must use HTTP or HTTPS.");
}

if (deleteConfig.method !== "DELETE") {
  throw new Error('delete.json must declare "method": "DELETE".');
}

if (!Array.isArray(deleteConfig.endpoints)) {
  throw new Error("delete.json must contain an endpoints array.");
}

for (const endpoint of deleteConfig.endpoints) {
  if (
    typeof endpoint.path !== "string" ||
    !endpoint.path.startsWith("/") ||
    endpoint.path.startsWith("//")
  ) {
    throw new Error(`Invalid DELETE endpoint: ${endpoint.path}`);
  }

  const url = new URL(endpoint.path, base);

  if (url.origin !== base.origin) {
    throw new Error(`Endpoint escapes target origin: ${endpoint.path}`);
  }
}

const defaults = deleteConfig.defaultTests ?? {};

function enabled(value) {
  return value === true || value?.enabled === true;
}

function testEnabled(endpoint, name) {
  if (endpoint.tests?.[name] !== undefined) {
    return enabled(endpoint.tests[name]);
  }

  return enabled(defaults[name]);
}

function safeToModify(endpoint) {
  return (
    config.security?.allowDestructiveTests === true &&
    endpoint.testRequest?.enabled === true
  );
}

function tokenFromEnv(envName) {
  return envName ? process.env[envName] : undefined;
}

async function sendDelete(endpoint, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const url = new URL(endpoint.path, base);

    const headers = {
      "user-agent": "VibeShield/0.1",
      accept: "application/json",
      ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
      ...(options.headers ?? {}),
    };

    return await fetch(url, {
      method: "DELETE",
      redirect: "manual",
      signal: controller.signal,
      headers,
      ...(options.body !== undefined
        ? {
            body: JSON.stringify(options.body),
            headers: {
              ...headers,
              "content-type": "application/json",
            },
          }
        : {}),
    });
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

const stackTracePattern =
  /(?:\bat\s+[\w$.<>]+\s+\([^)]*:\d+:\d+\)|Traceback \(most recent call last\)|Internal Server Error)/i;

describe("VibeShield configured DELETE endpoints", () => {
  describe("Configuration validation", () => {
    test("has a valid target and DELETE configuration", () => {
      expect(base.origin).toBeTruthy();
      expect(deleteConfig.method).toBe("DELETE");
      expect(Array.isArray(deleteConfig.endpoints)).toBe(true);
    });
  });

  describe("Availability", () => {
    test.each(deleteConfig.endpoints)(
      "DELETE $path handles a configured request",
      async (endpoint) => {
        if (!testEnabled(endpoint, "availability")) {
          return;
        }

        if (!safeToModify(endpoint)) {
          throw new Error(
            "Enable allowDestructiveTests and endpoint.testRequest.enabled " +
              "to run DELETE availability requests.",
          );
        }

        const response = await sendDelete(endpoint, {
          body: endpoint.testRequest.body,
        });

        expect(response.status).toBeLessThan(500);
      },
    );
  });

  describe("Authentication", () => {
    const cases = deleteConfig.endpoints.filter(
      (endpoint) =>
        testEnabled(endpoint, "authentication") && safeToModify(endpoint),
    );

    if (cases.length === 0) {
      test.skip("Authentication probes are not configured for safe execution", () => {});
    } else {
      test.each(cases)(
        "DELETE $path enforces its configured authentication mode",
        async (endpoint) => {
          const response = await sendDelete(endpoint, {
            body: endpoint.testRequest.body,
          });

          const authMode = endpoint.authMode ?? "protected";

          if (authMode === "protected") {
            expect([401, 403]).toContain(response.status);
          } else if (authMode === "public") {
            expect([401, 403]).not.toContain(response.status);
          } else {
            throw new Error(
              `Unsupported authMode "${authMode}" on ${endpoint.path}`,
            );
          }
        },
      );
    }
  });

  describe("Security misconfiguration", () => {
    const cases = deleteConfig.endpoints.filter(
      (endpoint) =>
        testEnabled(endpoint, "securityMisconfiguration") &&
        safeToModify(endpoint),
    );

    if (cases.length === 0) {
      test.skip("No eligible DELETE security-header probes configured", () => {});
    } else {
      test.each(cases)(
        "DELETE $path has secure response headers",
        async (endpoint) => {
          const response = await sendDelete(endpoint, {
            body: endpoint.testRequest.body,
          });

          expect(response.headers.get("x-powered-by")).toBeNull();
          expect(response.headers.get("x-content-type-options")).toBe(
            "nosniff",
          );
        },
      );
    }
  });

  describe("Injection probes", () => {
    const cases = deleteConfig.endpoints.filter((endpoint) => {
      const injection = endpoint.injectionTest;

      return (
        testEnabled(endpoint, "injection") &&
        safeToModify(endpoint) &&
        injection?.enabled === true &&
        Array.isArray(injection.payloads) &&
        injection.payloads.length > 0 &&
        Array.isArray(injection.fields) &&
        injection.fields.length > 0 &&
        endpoint.testRequest?.enabled === true
      );
    });

    if (cases.length === 0) {
      test.skip("No eligible DELETE injection probes configured", () => {});
    } else {
      test.each(cases)(
        "DELETE $path handles configured injection probes",
        async (endpoint) => {
          for (const field of endpoint.injectionTest.fields) {
            for (const payload of endpoint.injectionTest.payloads) {
              const body = structuredClone(endpoint.testRequest.body ?? {});

              body[field] = payload;

              const response = await sendDelete(endpoint, { body });
              const result = await readResponse(response);

              expect(result.status).toBeLessThan(500);
              expect(result.body).not.toMatch(stackTracePattern);
            }
          }
        },
      );
    }
  });

  describe("Exception handling", () => {
    const cases = deleteConfig.endpoints.filter(
      (endpoint) =>
        testEnabled(endpoint, "exceptionHandling") && safeToModify(endpoint),
    );

    if (cases.length === 0) {
      test.skip("No eligible DELETE exception-handling probes configured", () => {});
    } else {
      test.each(cases)(
        "DELETE $path does not expose obvious stack traces",
        async (endpoint) => {
          const response = await sendDelete(endpoint, {
            body: endpoint.testRequest.body,
          });

          const result = await readResponse(response);

          expect(result.body).not.toMatch(stackTracePattern);
        },
      );
    }
  });

  describe("Access control", () => {
    const accessControl = deleteConfig.accessControl;

    const accessEndpoints =
      accessControl?.enabled && Array.isArray(accessControl.endpoints)
        ? accessControl.endpoints
        : [];

    const accessCases = accessEndpoints.filter(
      (endpoint) =>
        endpoint.enabled !== false &&
        safeToModify(endpoint) &&
        endpoint.testRequest?.enabled === true,
    );

    if (accessCases.length === 0) {
      test.skip("No eligible DELETE access-control probes configured", () => {});
    } else {
      test.each(accessCases)(
        "DELETE $path rejects unauthorized access",
        async (endpoint) => {
          const unauthorizedToken = tokenFromEnv(
            accessControl.unauthorizedTokenEnv,
          );

          if (!unauthorizedToken) {
            throw new Error(
              "Access-control tests require an unauthorized token environment variable.",
            );
          }

          const unauthorized = await sendDelete(endpoint, {
            token: unauthorizedToken,
            body: endpoint.testRequest.body,
          });

          expect(endpoint.expectedUnauthorizedStatus ?? [401, 403]).toContain(
            unauthorized.status,
          );
        },
      );
    }
  });

  describe("Logging", () => {
    const cases = deleteConfig.endpoints.filter((endpoint) =>
      testEnabled(endpoint, "logging"),
    );

    test.todo(
      "Verify audit logging through application instrumentation or a log collector",
    );

    test("reports whether logging checks are configured", () => {
      expect(Array.isArray(cases)).toBe(true);
    });
  });
});
