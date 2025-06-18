require('dotenv').config()
const express = require('express');
const app = express();
const mongoose = require('mongoose');

app.use(express.json())

mongoose.connect(process.env.DATABASE_URL)
    .then(()=> console.log('MongoDB Connected'))
    .catch(err => console.log(err))

const { userRouter } = require('./routes/user');
app.use('/user', userRouter);

const {tasksRouter} = require('./routes/tasks');
app.use('/tasks', tasksRouter);

app.listen(3000, ()=> console.log('Server started on port 3000'));