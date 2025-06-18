require('dotenv').config()
const express = require('express');
const router = express.Router();
const User = require('../models/user');
const authenticateToken = require('../middleware/auth.js');

router.get('/get-all', authenticateToken, async (req, res) => {
    const userTasks = (await User.findById(req.userId)).tasks;
    res.send(userTasks);
})

module.exports = {tasksRouter:router};