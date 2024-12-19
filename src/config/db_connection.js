import mongoose from "mongoose";
import { DB_NAME } from "./constants.js";

export default async function connectToDB(){

    try {
        
        const connection = await mongoose.connect(process.env.DATABASE_URL + "/" + DB_NAME);

        console.log('connection successfull to DB' + connection);

    } catch (error) {
        
        console.log(error);
    }

};