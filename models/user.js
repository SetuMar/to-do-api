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
    tasks:[
        {
            title:String,
            description:String,
        }
    ]
})

module.exports = mongoose.model('User', userSchema)