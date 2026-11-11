import app from "./app.js";

const port = Number(process.env.PORT) || 3000;

app.listen(port, "127.0.0.1", () => {
  console.log(
    `VibeShield Test API listening at http://127.0.0.1:${port}`
  );
});