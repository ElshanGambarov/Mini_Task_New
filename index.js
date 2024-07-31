const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


dotenv.config();
const app = express();

app.use(bodyParser.json());
app.use(cors()); // CORS'u tüm uygulama için etkinleştir

const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    admin: { type: Boolean, default: false }
});

const UserModel = mongoose.model("User", UserSchema);

app.post("/signup", async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const newUser = new UserModel({
            username: req.body.username,
            password: hashedPassword,
        });
        await newUser.save();
        res.status(201).send({ message: "User created successfully" });
    } catch (error) {
        res.status(400).send({ message: "Error creating user", error });
    }
});

app.post("/login", async (req, res) => {
    try {
        const user = await UserModel.findOne({ username: req.body.username });
        if (user && await bcrypt.compare(req.body.password, user.password)) {
            const token = jwt.sign({ userId: user._id, admin: user.admin }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.send({ message: "Login successful", token });
        } else {
            res.status(401).send({ message: "Invalid username or password" });
        }
    } catch (error) {
        res.status(500).send({ message: "Error logging in", error });
    }
});



app.get("/admin", authenticateToken, (req, res) => {
    if (req.user.admin) {
        res.send({ message: "Welcome to admin page" });
    } else {
        res.status(403).send({ message: "Access denied" });
    }
});

function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send({ message: "No token provided" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send({ message: "Invalid token" });

        req.user = user;
        next();
    });
}


const CategorySchema = new mongoose.Schema({
    name: String,
    description: String
});

const CategoryModel = mongoose.model("Category", CategorySchema);

app.get("/categories", async (req, res) => {
    let categories = await CategoryModel.find();
    res.send(categories);
});

app.get("/categories/:id", async (req, res) => {
    let id = req.params.id;
    let category = await CategoryModel.findById(id);
    res.send(category);
});

app.delete("/categories/:id", async (req, res) => {
    let id = req.params.id;
    let category = await CategoryModel.findByIdAndDelete(id);
    res.send(category);
});

app.post("/categories", async (req, res) => {
    let newCategory = new CategoryModel(req.body);
    await newCategory.save();
    res.send(newCategory);
});

mongoose.connect(process.env.DB_Connection)
    .then(() => {
        console.log("Connected");
    })
    .catch(err => {
        console.log(err);
    });

app.listen(5050, () => {
    console.log("5050 portu aktivdir");
});