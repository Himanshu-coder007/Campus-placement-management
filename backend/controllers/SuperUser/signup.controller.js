const StudentUser = require("../../models/user.model");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const SignUp = async (req, res) => {
  const {
    first_name,
    middle_name,
    last_name,
    email,
    password,
    number,
    gender,
    dateOfBirth,
    fullAddress,
  } = req.body;

  try {
    // Check if user already exists
    const existingUser = await StudentUser.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ msg: "User with this email already exists!" });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const newUser = new StudentUser({
      first_name,
      middle_name,
      last_name,
      email,
      number,
      gender,
      dateOfBirth,
      fullAddress,
      password: hashedPassword,
      role: "superuser", // strictly assigning superuser role
    });

    // Generate JWT token
    const payload = { userId: newUser._id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    newUser.token = token;

    await newUser.save();

    res.status(201).json({ msg: "Superuser registered successfully", token });
  } catch (error) {
    console.error("signup.controller.js =>", error);
    res.status(500).json({ msg: "Internal Server Error!" });
  }
};

module.exports = SignUp;
