require('dotenv').config()

const express= require('express');
const app= express();

const jwt = require('jsonwebtoken');

const authenticateToken = require('./authenticateToken');

app.use(express.json());

const posts= [
    {
        userName: 'john',
        title: 'abc'
    },
    {
        userName: 'doe',
        title: 'def'
    }
]

app.get('/posts', authenticateToken, (req,res)=> {
    res.json(posts.filter(post=> post.userName===req.user.name))
})

app.post('/login', (req,res)=>{
    //Authenticate user

    const userName= req.body.userName;
    const user = {name: userName}
    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
    res.json({accessToken:accessToken})
})

app.listen(3000,()=>console.log('server started'))