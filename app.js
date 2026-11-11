import express from "express";

const app = express();

app.disable("x-powered-by");

// Security headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  next();
});

app.use(express.json({ limit: "100kb" }));

let nextId = 4;

let items = [
  { id: 1, name: "Notebook", description: "Plain notebook" },
  { id: 2, name: "Pen", description: "Blue ballpoint pen" },
  { id: 3, name: "Bottle", description: "Reusable water bottle" }
];

// Root endpoint
app.get("/", (_req, res) => {
  res.json({
    name: "VibeShield Test API",
    endpoints: [
      "GET /health",
      "GET /api/items",
      "GET /api/items/:id",
      "POST /api/items",
      "PUT /api/items/:id",
      "DELETE /api/items/:id"
    ]
  });
});

// Health check
app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

// GET: Retrieve all items
app.get("/api/items", (_req, res) => {
  res.status(200).json({
    count: items.length,
    items
  });
});

// GET: Retrieve one item
app.get("/api/items/:id", (req, res) => {
  const id = Number(req.params.id);
  const item = items.find((entry) => entry.id === id);

  if (!Number.isInteger(id) || !item) {
    return res.status(404).json({
      error: "Item not found"
    });
  }

  return res.status(200).json(item);
});

// POST: Create a new item
app.post("/api/items", (req, res) => {
  const { name, description = "" } = req.body ?? {};

  if (typeof name !== "string" || name.trim().length === 0) {
    return res.status(400).json({
      error: "name is required"
    });
  }

  const item = {
    id: nextId++,
    name: name.trim(),
    description:
      typeof description === "string" ? description : ""
  };

  items.push(item);

  return res.status(201).json(item);
});

// PUT: Update an existing item
app.put("/api/items/:id", (req, res) => {
  const id = Number(req.params.id);

  const index = items.findIndex(
    (entry) => entry.id === id
  );

  if (!Number.isInteger(id) || index === -1) {
    return res.status(404).json({
      error: "Item not found"
    });
  }

  const { name, description = "" } = req.body ?? {};

  if (typeof name !== "string" || name.trim().length === 0) {
    return res.status(400).json({
      error: "name is required"
    });
  }

  const updatedItem = {
    id,
    name: name.trim(),
    description:
      typeof description === "string" ? description : ""
  };

  items[index] = updatedItem;

  return res.status(200).json(updatedItem);
});

// DELETE: Delete an existing item
app.delete("/api/items/:id", (req, res) => {
  const id = Number(req.params.id);

  const index = items.findIndex(
    (entry) => entry.id === id
  );

  if (!Number.isInteger(id) || index === -1) {
    return res.status(404).json({
      error: "Item not found"
    });
  }

  const [deletedItem] = items.splice(index, 1);

  return res.status(200).json({
    message: "Item deleted",
    item: deletedItem
  });
});

// Handle malformed JSON
app.use((err, _req, res, next) => {
  if (err instanceof SyntaxError && "body" in err) {
    return res.status(400).json({
      error: "Invalid JSON body"
    });
  }

  return next(err);
});

export default app;