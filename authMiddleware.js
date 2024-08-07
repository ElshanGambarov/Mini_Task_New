const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization'];
    
    if (!token) {
        return res.status(401).json({ message: 'Access Denied. No Token Provided.' });
    }

    try {
        const decoded = jwt.verify(token, 'your_secret_key'); // 'your_secret_key' yerine kendi anahtarınızı kullanın.
        req.user = decoded;
        next();
    } catch (error) {
        res.status(400).json({ message: 'Invalid Token.' });
    }
};
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // 'Bearer ' kısmını ayırın
    if (token == null) return res.status(401).send({ message: "No token provided" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send({ message: "Invalid token" });

        req.user = user;
        next();
    });
}
module.exports = authMiddleware;