const mongoose = require("mongoose");
const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
const path = require("path");
const secretKey = "yasir@1";
app.use(express.json());

mongoose.connect("mongodb://localhost:27017/userapp")
  .then(() => {
    console.log("MongoDB connected");
  })
  .catch((err) => {
    console.log("Internal error", err);
  });
  
// Schema for User
app.use(express.static(path.join(__dirname, "public")));
const userSchema = new mongoose.Schema({
  userName: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);
const userTokens = {}; 

// Signup /Create User
app.post("/signup", async (req, res) => {
  let userName= req.body.userName;
  let password= req.body.password;
  let name = req.body.name;
  
  try {
    // Check if user already exists
    const userExist = await User.findOne({ userName });
    if (userExist) {
      return res.status(400).json({ message: "User already exists" });
    }
    // Create and save a new user
    const newUser = new User({
      userName,
      name,
      password,
    });
    await newUser.save();
    res.status(201).json({ message: "User signed up successfully", newUser });
  } catch (error) {
    res.status(500).json({ message: "Error signing up user", error });
  }
});

// Login User
app.post("/login", async (req, res) => {
  const { userName, password } = req.body;
  try {
    const user = await User.findOne({ userName, password });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    const token = jwt.sign(
      { userName: user.userName, name: user.name,},
      secretKey
    );
    userTokens[user.userName] = token;
    res.status(200).json({
      message: "Login successful",
      token,
    });
  } catch (error) {
    res.status(500).json({ message: "Error logging in", error });
  }
});



// Middleware to authenticate token
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ message: "Token required" });
  }

  // Token Verification 
  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    if (userTokens[user.userName] !== token) {
      return res.status(403).json({ message: "Token is no longer valid" });      
    }
    req.user = user;
    next();
  });
}
// Get User Profile Endpoint
app.get("/user/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ userName: req.user.userName });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ message: "Error fetching user data", error });
  }
});

// Update User
app.put("/user/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { name, password } = req.body;
  try {
    // Check if the user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    // Update user details
    user.name = name || user.name;   // Checking username and name is not empty there
    user.password = password || user.password;
    await user.save();
    res.status(200).json({ message: "User updated successfully", user });
  } catch (error) {
    res.status(500).json({ message: "Error updating user", error });
  }
});


// Delete User
app.delete("/user/:userId", authenticateToken, async (req, res) => {
  const { userId } = req.params;
  try {
    const user = await User.findByIdAndDelete(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    // Remove token for the deleted user
    delete userTokens[user.userName];
    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting user", error });
  }
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});

