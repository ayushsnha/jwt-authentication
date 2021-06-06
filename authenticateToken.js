const jwt = require('jsonwebtoken')

const authenticateToken=(req, res, next)=> {
    const  authHeader= req.headers;
    const token= authHeader['authorization'] && authHeader['authorization'].split(' ')[1];
    if(token == null)
        return res.sendStatus(401)
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err,user)=> {
        if (err)
            return res.sendStatus(403);
        req.user = user;
        next();    
    })
    
}

module.exports= authenticateToken;