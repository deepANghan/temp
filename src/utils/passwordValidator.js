export default function validatePassword(password) {
    
    const minLength = 8;
  
    // Check length
    if (password.length < minLength) {
      return {status:false, message:"Password must be at least 8 characters long."};
    }
  
    // Example: Check if the password contains at least 1 number
    if (!/\d/.test(password)) {
      return {status:false, message:"Password must contain at least one number."};
    }
  
    // Example: Check if the password contains at least 1 special character
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      return {status:false, message:"Password must contain at least one special character."};
    }
  
    // Example: Check if the password contains at least 1 uppercase letter
    if (!/[A-Z]/.test(password)) {
      return {status:false, message:"Password must contain at least one uppercase letter."};
    }
  
    // If all checks pass
    return {status: true, message: "Password is valid."};
  }