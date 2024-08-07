require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();

app.use(bodyParser.json());
app.use(cors());

// Kullanıcı Şeması ve Modeli
const UserSchema = new mongoose.Schema({
    username: String,
    email: { type: String, unique: true },
    password: String,
    admin: { type: Boolean, default: false }
});

const UserModel = mongoose.model("User", UserSchema);

// Kullanıcı Kayıt
app.post("/auth/signup", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).send({ message: "All fields are required" });
        }

        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
            return res.status(400).send({ message: "Email already exists" });
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).send({ message: "Password does not meet the required criteria" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new UserModel({
            username,
            email,
            password: hashedPassword,
        });
        await newUser.save();
        res.status(201).send({ message: "User created successfully" });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(400).send({ message: "Error creating user", error });
    }
});

// Kullanıcı Giriş
app.post("/auth/login", async (req, res) => {
    try {
        const user = await UserModel.findOne({ email: req.body.email });
        if (user && await bcrypt.compare(req.body.password, user.password)) {
            if (!user.admin) {
                return res.status(403).send({ message: "Access denied. Admin privileges required." });
            }

            const token = jwt.sign({ userId: user._id, admin: user.admin }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.send({ message: "Login successful", token });
        } else {
            res.status(401).send({ message: "Invalid email or password" });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send({ message: "Error logging in", error });
    }
});

// Admin Sayfası
app.get("/admin", authenticateToken, (req, res) => {
    if (req.user.admin) {
        res.send({ message: "Welcome to admin page" });
    } else {
        res.status(403).send({ message: "Access denied" });
    }
});

// Kategori Şeması ve Modeli
const categorySchema = new mongoose.Schema({
    title: { type: String, required: true },
    price: { type: Number, required: true },
    description: { type: String, required: true },
    categories: { type: String, required: true },
    img: { type: String, required: true }
});

const Category = mongoose.model('Category', categorySchema);

// JWT doğrulama middleware'ı
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

// Kategorileri al
app.get('/categories', authenticateToken, async (req, res) => {
    try {
        const categories = await Category.find();
        res.json(categories);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching categories' });
    }
});

// Kategori oluştur
app.post('/categories', authenticateToken, async (req, res) => {
    try {
        const category = new Category(req.body);
        await category.save();
        res.status(201).json(category);
    } catch (error) {
        res.status(400).json({ error: 'Error creating category' });
    }
});

// Kategori güncelle
app.put('/categories/:id', authenticateToken, async (req, res) => {
    try {
        const category = await Category.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!category) return res.status(404).json({ error: 'Category not found' });
        res.json(category);
    } catch (error) {
        res.status(400).json({ error: 'Error updating category' });
    }
});

// Kategori sil
app.delete('/categories/:id', authenticateToken, async (req, res) => {
    try {
        const result = await Category.findByIdAndDelete(req.params.id);
        if (!result) return res.status(404).json({ error: 'Category not found' });
        res.json({ message: 'Category deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Error deleting category' });
    }
});

// MongoDB'ye bağlan
mongoose.connect(process.env.DB_CONNECTION)
    .then(() => {
        console.log("Connected to MongoDB");
        app.listen(5050, () => {
            console.log("Server running on port 5050");
        });
    })
    .catch(err => {
        console.error('Error connecting to MongoDB:', err);
    });