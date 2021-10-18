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

app.post('/api/token', (req,res)=> {
    const refreshToken = req.body.token;
    if (refreshToken== null) return res.sendStatus(401);
    if(!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err,user)=>{
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({name: user.name});
        res.json({accessToken:accessToken})
    })
})

app.post('/api/verify', (req,res)=> {
    const token = req.body.token;
    console.log(req.body)
    if (token== null) return res.sendStatus(401);
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err,user)=>{
        if (err) return res.sendStatus(403);
        res.status(200).json('success');
    })
})

app.delete('/api/logout', (req,res)=> {
    refreshTokens= refreshTokens.filter(token=>token!==req.body.token)
    res.sendStatus(204)
})
app.get('/api', (req,res)=> {
    res.status(200).json('Success')
})

app.post('/api/register', (req,res)=>{
    const { name, email, password}= req.body;
    console.log(req.body)
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

app.post('/api/login', (req,res)=>{
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
            const refreshToken = jwt.sign({id: user._id}, process.env.REFRESH_TOKEN_SECRET,{expiresIn: '50s'});
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
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '70s'});
}


app.listen(4000,()=>console.log('Auth server started'))