import express from "express";
import { createServer } from "http";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import authRouter from "./routes/authRoute.js";
import { authenticateToken } from "./middleware/authMiddleware.js";

const app = express();
const server = createServer(app);
app.use(cors());
app.use(express.json());
dotenv.config();

app.use(
  cors({
    origin: "http://SudhinDevan.com",
    methods: "GET,POST",
    allowedHeaders: "Content-Type,Authorization",
  })
);
//All the authentication routes are kept in the below authController and those should not be authenticated by any middleware as they are not having any tokens as of now. All the public routes should be kept below this and above the middleware that is authenticating the token.
app.use("/", authRouter);

app.use(authenticateToken);

//all the routes after the user has logged in should be kept below this so that at all the api calls the request passes through this middleware and makes sure an authorized user is logged in which makes the security higher.
// also if the user is blocked by the admin when the session for the user is going on or while the user is logged in, in that case by the next api call the user can be redirected to the login by successfull logout.
// for the above condition to work the middleware should be modified to check that. Also, it can be done by interceptors.

const db = process.env.DATABASE;
const port = process.env.PORT;
mongoose
  .connect(db)
  .then(() => {
    server.listen(port);
    console.log("Database connected and listening on port:", port);
  })
  .catch((err) => console.log(err));
