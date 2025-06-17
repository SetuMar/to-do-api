require('dotenv').config()
const express = require('express');
const router = express.Router();
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

router.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({name: req.body.name});

        if (!user) res.status(404).send('User not found');
        res.user = user;

        // hash sent in password and see if it matches password (avoid rainbow table attacks)
        const isMatch = await bcrypt.compare(req.body.password, user.password)
        if (!isMatch) res.status(400).send('Invalid Credentials')
        else {
            const accessToken = jwt.sign({userId: user._id}, process.env.ACCESS_TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: '30s'
            });

            const refreshToken = jwt.sign({userId: user._id}, process.env.REFRESH_TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: '7d'
            });

            user.refreshToken = refreshToken;
            await user.save();

            res.json({accessToken: accessToken, refreshToken: refreshToken});
        }
    } catch (error) {
        return res.status(401).send({error: error.message});
    }
})

router.post('/create', checkValidUsername, async (req, res) => {
    if (res.validUsername) {
        // hash password with bcrypt to avoid rainbow table attacks
        const hashedPassword = await bcrypt.hash(req.body.password, 12);

        const user = new User({
            name: req.body.name,
            password: hashedPassword,
        })

        try {
            const newSubscriber = await user.save()
            res.status(201).json(newSubscriber)
        } catch (err) {
            res.status(400).json({error: err.message})
        }
    } else {
        res.send("User already exists")
    }
})

router.post('/refresh', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const refreshToken = authHeader && authHeader.split(' ')[1];

        if (!refreshToken) {
            return res.status(401).json({ message: 'No refresh token provided' });
        }

        const user = await User.findOne({refreshToken: refreshToken});
        if (!user) return res.status(403).json({ message: 'Invalid refresh token' });

        try {
            const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

            const accessToken = jwt.sign({userId: payload.userId}, process.env.ACCESS_TOKEN_SECRET, {
                algorithm: 'HS256',
                expiresIn: '30s'
            });

            // Generate a new access token here using payload info
            res.json({ "New AccessToken": accessToken });
        } catch (err) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

    } catch (err) {
        res.send({error: err.message})
    }
})

router.get('/gettasks', authenticateToken, async (req, res) => {
    const result = await User.findOne({ _id: req.userId });
    if (!result) {
        return res.status(404).send('User not found');
    }

    res.json(result.tasks)
})

async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    // if the header exists and get the token
    const token = authHeader && authHeader.split(' ')[1];

    // invalid token
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ error: 'Access token expired' });
            }

            console.error("JWT verification error:", err.message);
            return res.sendStatus(403).json({error:'Invalid token'});
        }
        req.userId = user.userId;
        next();
    });
}

async function checkValidUsername(req, res, next) {
    try {
        const user = await User.findOne({name: req.body.name});
        res.validUsername = !user;
        next();
    } catch (error) {
        res.status(401).send({error: error.message});
    }
}

module.exports = router;