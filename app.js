require('dotenv').config()

const express= require('express');
const app= express();

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

app.listen(3000,()=>console.log('server started'))