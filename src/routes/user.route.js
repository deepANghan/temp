import { Router } from "express";
import { signupUser, loginUser, logoutUser } from "../controllers/user.controllers.js";
import { verifyJWT } from "../utils/verifyJWT.js";

export const userRouter = Router();

userRouter.post('/signup', signupUser);
userRouter.post('/login', loginUser);
userRouter.get('/logout', verifyJWT ,logoutUser);