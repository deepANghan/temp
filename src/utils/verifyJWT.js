import { ApiErrorResponse } from "./apiError.js";
import jwt from 'jsonwebtoken';

export function verifyJWT(req, res, next){

    try {
        
        const userToken = req.cookies.accessToken;

        if(!userToken){
            throw new ApiErrorResponse(401, "token is empty");
        }

        const isValid = jwt.verify(userToken, process.env.ACESSTOKEN_SECRET);

        if(!isValid){
            throw new ApiErrorResponse(400, "token is invalid");
        }

        console.log(isValid);

        req.user_id = isValid.user_id;
        req.role = isValid.role;

        next();

    } catch (error) {
        
        res.status(400).json(error);
    }

}