const mongoose = require('mongoose');
const taskSchema = require('./task.js')

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    refreshToken: {
        type: String,
        default: null
    },
})

module.exports = mongoose.model('User', userSchema)