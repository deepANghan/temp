import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
    
    full_name:{
        type:String,
        required:true
    },

    email:{
        type:String,
        required:true,
        unique:true,
        lowercase:true,
        trim:true
    },

    password:{
        type:String,
        required:true
    },

    role:{
        type:String,
        default:'Student',
        enum:['admin', 'instructor', 'student']
    }

}, {
    timestamps:true
});

export const user = mongoose.model('user', UserSchema);