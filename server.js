const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
require('dotenv').config();
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

mongoose.connect(process.env.URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log("DB connected");
}).catch((err) => {
    console.error("Error connecting to database:", err);
});

const userSchema = new mongoose.Schema({
    fname: String,
    lname: String,
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
});

userSchema.pre("save", async function(next) {
    try {
        // Hash the password before saving
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(this.password, salt);
        this.password = hashedPassword;
        next();
    } catch (error) {
        next(error);
    }
});

const User = mongoose.model("User", userSchema);

//Routes
app.post("/login", async(req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email: email });
        if (!user) {
            return res.status(401).json({ message: "Invalid email or password" });
        }
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: "Invalid email or password" });
        }
        res.status(200).json({ message: "Login successfully", user: user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});

app.post("/signup", async(req, res) => {
    const { fname, lname, email, password } = req.body;
    try {
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return res.status(400).json({ message: "User is already registered" });
        }
        const newUser = new User({
            fname,
            lname,
            email,
            password,
        });
        await newUser.save();
        res.status(201).json({ message: "Account has been created!! Please Login" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});

const PORT = process.env.PORT || 8001;
app.listen(PORT, () => {
    console.log(`Server starting at ${PORT}`);
});