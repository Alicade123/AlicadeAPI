const express = require("express");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = 3000; // Directly define PORT here
const JWT_SECRET = "yourSuperSecretKey"; // Directly define JWT_SECRET here

app.use(express.json());

// PostgreSQL connection pool - Hardcoding DB credentials
const pool = new Pool({
  host: "dpg-d08e2dhr0fns73btkou0-a", // DB Host
  user: "postgre", // DB User
  password: "KogCYgJNylIH5wrVuixjb4WL8jgtb0cj", // DB Password
  database: "e_commerce_yn7z", // DB Name
  port: 5432, // DB Port
});

// ---------------------------
// User Signup Route
// ---------------------------
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const existingUser = await pool.query(
      "SELECT * FROM usersapi WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO usersapi (username, email, password) VALUES ($1, $2, $3)",
      [username, email, hashedPassword]
    );

    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Signup failed, please try again later" });
  }
});

// ---------------------------
// User Login Route
// ---------------------------
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const userResult = await pool.query(
      "SELECT * FROM usersapi WHERE email = $1",
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = userResult.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "45d",
    });

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed, please try again later" });
  }
});

// ---------------------------
// JWT Authentication Middleware
// ---------------------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

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
// GET All Products
// ---------------------------
app.get("/products", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM productsapi");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

// ---------------------------
// GET Product by ID
// ---------------------------
app.get("/products/:id", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM productsapi WHERE productid = $1",
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch product" });
  }
});

// ---------------------------
// POST New Product
// ---------------------------
app.post("/products", authenticateToken,async (req, res) => {
  const { productName, description, quantity, price } = req.body;

  if (!productName || !quantity || !price) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const result = await pool.query(
      "INSERT INTO productsapi (productname, description, quantity, price) VALUES ($1, $2, $3, $4) RETURNING productid",
      [productName, description, quantity, price]
    );

    res.status(201).json({
      message: "Product added",
      productId: result.rows[0].productid,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to add product" });
  }
});

// ---------------------------
// PUT Update Product
// ---------------------------
app.put("/products/:id", authenticateToken, async (req, res) => {
  const { productName, description, quantity, price } = req.body;

  try {
    const result = await pool.query(
      "UPDATE productsapi SET productname = $1, description = $2, quantity = $3, price = $4 WHERE productid = $5",
      [productName, description, quantity, price, req.params.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json({ message: "Product updated" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update product" });
  }
});

// ---------------------------
// DELETE Product
// ---------------------------
app.delete("/products/:id", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM productsapi WHERE productid = $1",
      [req.params.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json({ message: "Product deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete product" });
  }
});

// ---------------------------
// PATCH Product Fields
// ---------------------------
app.patch("/products/:id", authenticateToken, async (req, res) => {
  const updates = req.body;

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: "No fields to update" });
  }

  try {
    const fields = Object.keys(updates)
      .map((field, idx) => `${field} = $${idx + 1}`)
      .join(", ");
    const values = Object.values(updates);
    values.push(req.params.id);

    const result = await pool.query(
      `UPDATE productsapi SET ${fields} WHERE productid = $${values.length}`,
      values
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json({ message: "Product updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update product" });
  }
});

// ---------------------------
// Start Server
// ---------------------------
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
