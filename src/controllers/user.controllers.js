import { z } from 'zod';
import validatePassword from '../utils/passwordValidator.js';
import { ApiErrorResponse } from '../utils/apiError.js';
import { user } from '../models/user.model.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const signupSchema = z.object({
    full_name: z.string().min(5, "full name must be of length 5").regex(/[a-zA-z]{5,}/, "please provide characters only"),
    email:z.string().email("email isn't valid"),
    role:z.enum(['admin', 'student', 'instructor'])
});

export async function signupUser(req, res){

    try {
        
        const { full_name, email, password, role } = req.body;

        const userData = signupSchema.safeParse({
            full_name,
            email,
            role
        });

        if(!userData.success){
            throw new ApiErrorResponse(400, userData.error.issues[0].message)
        }

        const { status, message } = validatePassword(password);

        if(!status){
            throw new ApiErrorResponse(400, message);
        }

        const isUserExist = await user.findOne({
            email:email
        });

        if(isUserExist){
            throw new ApiErrorResponse(400, "user already exist");
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const createdUser = await user.create({
            full_name: full_name,
            email: email,
            password: hashedPassword,
            role: role
        });

        if(!createdUser){
            throw new ApiErrorResponse(500, "user creation failed");
        }

        return res.status(201).json({
            status:201,
            message:"user signed up successfull",
            createdUser
        });


    } catch (error) {

        return res.status(400).json(error);

    }
}

function generateAccessToken(userData){

    const token = jwt.sign(
        {
            user_id: userData._id,
            role: userData.role
        },
        process.env.ACESSTOKEN_SECRET,
        {
            expiresIn:"24h"
        }
    );

    return token;

}

export async function loginUser(req, res){

    try {
        
        const { email, password, role } = req.body;

        if(!email){
            throw new ApiErrorResponse(400, "email is empty");
        }

        if(!password){
            throw new ApiErrorResponse(400, "password is empty");
        }

        if(!role){
            throw new ApiErrorResponse(400, "role is empty");
        }

        const isUserExist = await user.findOne({
            email: email,
            role: role
        });

        if(!isUserExist){
            throw new ApiErrorResponse(400, "please signup first");
        }

        const isPasswordValid = await bcrypt.compare(password, isUserExist.password);

        if(!isPasswordValid){
            throw new ApiErrorResponse(400, "password is wrong");
        }

        const accessToken = generateAccessToken(isUserExist);

        const options = {
            httpOnly: true
        }

        return res.status(200).cookie("accessToken", accessToken, options)
        .json({
            status:200,
            message:"login successfull"
        });

    } catch (error) {
        
        return res.status(400).json(error);

    }

}

export function logoutUser(req, res){

    return res.status(200).clearCookie('accessToken')
    .json({
        status:200,
        message:"logged out successfully"
    });

}


