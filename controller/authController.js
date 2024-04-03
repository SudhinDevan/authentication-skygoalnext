import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import user from "../model/user.js";

let jwtPrivateKey = process.env.JWT_SECRET_KEY;
let refreshTokenKey = process.env.JWT_SECURE_KEY;

const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    let existingUser = await user.findOne({ email: email });

    if (existingUser) {
      //to check if already user exists
      return res.status(400).json({
        message: "This user already exists! Please Login",
      });
    }
    const saltRounds = 10;
    const genSalt = bcrypt.genSaltSync(saltRounds);
    const hashedPassword = bcrypt.hashSync(password, genSalt);

    //saving name, email, and password add more details that is collected from the user here.
    const newUser = new user({
      name,
      email,
      password: hashedPassword,
    });
    await newUser.save();

    return res.json({
      error: false,
      message: "Registration Successful",
      user: newUser,
    });
  } catch (error) {
    console.error("Error in signup: ", error);
    return res.status(500).json({
      error: true,
      message: "Internal server error",
    });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    let existingUser;
    existingUser = await user.findOne({ email: email });

    if (!existingUser) {
      return res.status(404).json({ message: "User does not exist" });
    }
    const isPasswordCorrect = bcrypt.compareSync(
      password,
      existingUser.password
    );
    if (!isPasswordCorrect) {
      res.status(401).json({ message: "Invalid Credentials" });
      return;
    }

    const accessToken = jwt.sign({ userId: existingUser._id }, jwtPrivateKey, {
      expiresIn: "30m",
    });
    const refreshToken = jwt.sign(
      { userId: existingUser._id },
      refreshTokenKey,
      {
        expiresIn: "1d",
      }
    );

    res.cookie("jwt", refreshToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    });

    existingUser.refreshToken = refreshToken;
    await existingUser.save();

    const sanitizedUser = {
      //avoiding sending the whole details to the frontend
      id: existingUser.id,
      name: existingUser.name,
      phone: existingUser.phone,
      email: existingUser.email,
    };

    res.status(200).json({
      message: "login successfull",
      user: sanitizedUser,
      accessToken,
    });
  } catch (error) {
    console.error("Error in login:", error);
    return res
      .status(500)
      .json({ error: true, message: "Internal server error" });
  }
};

const userLogout = async (req, res) => {
  try {
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(204);
    const refreshToken = cookies.jwt;

    const userData = await user.findOne({ refreshToken: refreshToken });
    if (!userData) {
      res.clearCookie("jwt", { httpOnly: true });
      return res.sendStatus(204);
    }
    userData.refreshToken = "";
    await userData.save();

    res.clearCookie("jwt", { httpOnly: true });
    res.sendStatus(204);
  } catch (error) {
    console.error("Error in userLogout:", error);
    return res
      .status(500)
      .json({ error: true, message: "Internal server error" });
  }
};

export { signup, login, userLogout };
