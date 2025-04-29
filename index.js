require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(express.json());

// DB Connection function
async function getDBConnection() {
  return await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
  });
}

// ---------------------------
// User Signup Route
// ---------------------------
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const db = await getDBConnection();

    const [existing] = await db.execute(
      "SELECT * FROM usersapi WHERE email = ?",
      [email]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute(
      "INSERT INTO usersapi (username, email, password) VALUES (?, ?, ?)",
      [username, email, hashedPassword]
    );

    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// ---------------------------
// User Login Route
// ---------------------------
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const db = await getDBConnection();

    const [users] = await db.execute("SELECT * FROM usersapi WHERE email = ?", [
      email,
    ]);

    if (users.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = users[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign({ id: user.id, email }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ---------------------------
// JWT Authentication Middleware
// ---------------------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ error: "Token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }

    req.user = user;
    next();
  });
}

// ---------------------------
// GET All Products (Protected)
// ---------------------------
app.get("/products", authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    const [rows] = await db.execute("SELECT * FROM productsapi");
    res.json(rows);
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

// ---------------------------
// GET Product by ID (Protected)
// ---------------------------
app.get("/products/:id", authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    const [rows] = await db.execute(
      "SELECT * FROM productsapi WHERE productId = ?",
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ error: "Failed to fetch product" });
  }
});

// ---------------------------
// POST New Product (Protected)
// ---------------------------
app.post("/products", authenticateToken, async (req, res) => {
  const { productName, description, quantity, price } = req.body;

  if (!productName || !quantity || !price) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const db = await getDBConnection();
    const [result] = await db.execute(
      "INSERT INTO productsapi (productName, description, quantity, price) VALUES (?, ?, ?, ?)",
      [productName, description, quantity, price]
    );

    res
      .status(201)
      .json({ message: "Product added", productId: result.insertId });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ error: "Failed to add product" });
  }
});

// ---------------------------
// PUT Update Product (Protected)
// ---------------------------
app.put("/products/:id", authenticateToken, async (req, res) => {
  const { productName, description, quantity, price } = req.body;

  try {
    const db = await getDBConnection();
    const [result] = await db.execute(
      "UPDATE productsapi SET productName = ?, description = ?, quantity = ?, price = ? WHERE productId = ?",
      [productName, description, quantity, price, req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json({ message: "Product updated" });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ error: "Failed to update product" });
  }
});

// ---------------------------
// DELETE Product (Protected)
// ---------------------------
app.delete("/products/:id", authenticateToken, async (req, res) => {
  try {
    const db = await getDBConnection();
    const [result] = await db.execute(
      "DELETE FROM productsapi WHERE productId = ?",
      [req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json({ message: "Product deleted" });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ error: "Failed to delete product" });
  }
});

// ---------------------------
// PATCH Update Product Fields (Protected)
// ---------------------------
app.patch("/products/:id", authenticateToken, async (req, res) => {
  const updates = req.body;

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: "No fields to update" });
  }

  try {
    const db = await getDBConnection();

    const fields = Object.keys(updates)
      .map((field) => `${field} = ?`)
      .join(", ");
    const values = Object.values(updates);
    values.push(req.params.id);

    const [result] = await db.execute(
      `UPDATE productsapi SET ${fields} WHERE productId = ?`,
      values
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json({ message: "Product updated successfully" });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ error: "Failed to update product" });
  }
});

// ---------------------------
// Start Server
// ---------------------------
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
