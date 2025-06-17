const mongoose = require('mongoose');

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
    tasks:[
        {
            title:String,
            description:String,
        }
    ]
})

module.exports = mongoose.model('User', userSchema)