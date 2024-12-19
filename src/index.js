import express from 'express';
import connectToDB from './config/db_connection.js';
import dotenv from 'dotenv';
import { userRouter } from './routes/user.route.js';
import { verifyJWT } from './utils/verifyJWT.js';
import cookieParser from 'cookie-parser';

dotenv.config();

const app = express();
const PORT = 8080 || process.env.PORT;

app.use(cookieParser());
app.use(express.json());

app.use('/api/user', userRouter);
app.use(express.urlencoded({extended: true}));

app.post('/', verifyJWT ,(req, res) => {

    console.log(req.user_id, req.role);

    res.json({
        message:"home page accessed"
    });

});


connectToDB()
.then((res) => {
    // console.log(res)
})
.catch((error) => {
    console.log(error);
});


app.listen(PORT, () => console.log(`server started on Port ${PORT}`));