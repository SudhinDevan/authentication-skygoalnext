import express from "express";
const router = express.Router();

import { login, userLogout, signup } from "../controller/authController.js";

router.post("/login", login);
router.post("/signup", signup);
router.get("/logout", userLogout);

export default router;
