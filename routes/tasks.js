require('dotenv').config()
const express = require('express');
const router = express.Router();
const User = require('../models/user');
const authenticateToken = require('../middleware/auth.js');
const Task = require('../models/task');

async function getUser(id) {
    return User.findById(req.userId)
}

router.patch('/add', authenticateToken, async (req, res) => {
    const { title, description } = req.body;

    const task = new Task({
        title,
        description,
        userId: req.userId // middleware will handle this
    });

    try {
        const savedTask = await task.save();
        res.status(201).json(savedTask);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
})

module.exports = {tasksRouter:router};