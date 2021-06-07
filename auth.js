require('dotenv').config()
const express= require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');


const app= express();

const jwt = require('jsonwebtoken');

app.use(express.json());

const User = require('./models/user')

let refreshTokens=[];

mongoose.connect(process.env.MONGOURI,{
    useNewUrlParser:true,
    useUnifiedTopology: true,
    useCreateIndex: true,
    useFindAndModify: false
    })
    .then(()=> console.log('Connected to Database!!'))
    .catch(err=>console.log(err))    

app.post('/token', (req,res)=> {
    const refreshToken = req.body.token;
    if (refreshToken== null) return res.sendStatus(401);
    if(!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err,user)=>{
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({name: user.name});
        res.json({accessToken:accessToken})
    })
})

app.delete('/logout', (req,res)=> {
    refreshTokens= refreshTokens.filter(token=>token!==req.body.token)
    res.sendStatus(204)
})

app.post('/register', (req,res)=>{
    const { name, email, password}= req.body;
    if(!name || !email || !password)
        return res.status(400).json({message: "Invalid field"})

    User.findOne({email})
    .then(user=>{
        if(user) return res.status(400).json({message: 'User already exists'});
        const newUser = new User({
            name,
            email,
            password
        });

        bcrypt.hash(newUser.password, 10, (err,hash)=>{
            console.log(hash)
            newUser.password = hash;
            newUser.save()
            .then(user=>{
                const accessToken = generateAccessToken({id: user._id});
                const refreshToken = jwt.sign({id: user._id}, process.env.REFRESH_TOKEN_SECRET)
                User.findOneAndUpdate({_id: user._id},{refresh_token: refreshToken})
                .then(user=>console.log(user));
                res.json({
                    accessToken,
                    refreshToken,
                    user: {
                        id: user._id,
                        name: user.name,
                        email: user.email
                    }
                })
            })
            .catch(err=>console.log(err)) 
        })
    })

})

app.post('/login', (req,res)=>{
    const {email, password}= req.body;
    if(!email || !password)
        return res.status(400).json({message: "Invalid field"})

    User.findOne({email})
    .then(user=>{
        if(!user) return res.status(400).json({message: 'User not exists'});
        bcrypt.compare(password, user.password)
        .then(isMatch=>{
            if(!isMatch) return res.status(400).json({message: 'Invalid Credential!!'});
            const accessToken = generateAccessToken({id: user._id});
            const refreshToken = jwt.sign({id: user._id}, process.env.REFRESH_TOKEN_SECRET,{expiresIn: '500s'});
            User.findOneAndUpdate({_id: user._id},{refresh_token: refreshToken}, {new:true})
            .then(user=>console.log(user));
            res.json({
                accessToken,
                refreshToken,
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email
                }
            })
        })
    })
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '20s'});
}


app.listen(4000,()=>console.log('Auth server started'))