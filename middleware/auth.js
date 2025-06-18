const jwt = require("jsonwebtoken");

async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    // if the header exists and get the token
    const token = authHeader && authHeader.split(' ')[1];

    // invalid token
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ error: 'Access token expired' });
            }

            console.error("JWT verification error:", err.message);
            return res.sendStatus(403).json({error:'Invalid token'});
        }
        req.userId = user.userId;
        next();
    });
}

module.exports = authenticateToken;