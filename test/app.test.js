import request from "supertest";
import { describe, test, expect } from "@jest/globals";
import app from "../src/app.js";

describe("VibeShield API", () => {
  test("GET /health returns healthy status", async () => {
    const response = await request(app).get("/health");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ok" });
  });

  test("GET /api/v1 returns API metadata", async () => {
    const response = await request(app).get("/api/v1");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      name: "VibeShield",
      version: "0.1.0",
      message: "Backend is running",
    });
  });

  test("unknown routes return JSON 404", async () => {
    const response = await request(app).get("/does-not-exist");

    expect(response.status).toBe(404);
    expect(response.body).toEqual({ error: "Not found" });
  });
});
