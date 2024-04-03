import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const jwtPrivateKey = process.env.JWT_SECRET_KEY;

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader?.startsWith("Bearer ")) return res.sendStatus(401);
    const token = authHeader.split(" ")[1];
    jwt.verify(token, jwtPrivateKey, (err, decoded) => {
      if (err) return res.sendStatus(403);
      req.userId = decoded.userId;
      next();
    });
};

export { authenticateToken };
