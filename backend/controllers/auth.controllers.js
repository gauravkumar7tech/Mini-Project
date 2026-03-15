import User from '../models/User.js';
import jwt from 'jsonwebtoken';
import auth from '../Middleware/auth.js';
 const generateTaken = (id) => {
    return jwt.sign({id},process.env.JWT_SECRET,{
        expiresIn:'7d',
    });
};


const registerUser = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({message: 'Please provide all required fields'
            });
        }

        const exists = await User.findOne({ email });
        if (exists) {
            return res.status(400).json({message: 'User already exists'
            });
        }

        const user = await User.create({
            name,
            email,
            password
        });

        const userResponse = {
            _id: user._id,
            name: user.name,
            email: user.email,
        }

        const token = generateTaken(user._id);
        res.cookie('token', token,{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        })
        res.status(201).json({
            user: userResponse,
            message: 'User registered successfully'
        });
        
    } catch (error) {
        console.error('Registeration error:',error);
        res.status(500).json({
            success: false,
            message: 'Server error during registration'
        });
    }
};

export const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({message: 'Please provide email and password'});
        }

        // find user and cheak password
        const user = await User.findOne({ email });
        if (!user || !(await user.matchPassword(password))) {
            return res.status(401).json({message: 'Invalid credentials'});
        }

        //premove password from respones
        const userResponse = {
            _id: user._id,
            name: user.name,
            email: user.email,
        }

        //Set HTTP-only cookie
        const token = generateTaken(user._id);
        res.cookie('token', token,{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        })
        res.json({
            user: userResponse,
            message: 'Login successful'
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            message: 'Server error during login'
        });
    }
};

// Get current user from cookie

export const getMe = async (req, res) => {
    try {
        const token = req.cookie('token');
        if (!token) {
            return res.status(401).json({message: 'No token provided'});
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        if(!user){
            return res.status(404).json({message: 'User not found'});
        }
        res.json({
            user:{
            _id : user._id,
            name : user.name,
            email : user.email,
            }
        });

    }catch(error){
        console.error('GetMe error:', error);
        res.status(500).json({
            message: 'Invalid token'
        });
    }
};

export const layout = async (req, res) => {
    try{
        res.clearCookie('token');
        res.json({message: 'Logged out successful'});
        }catch(error){
        console.error('Logout error:', error);
        res.status(500).json({
            message: 'Server error during logout'
        });
    }
};