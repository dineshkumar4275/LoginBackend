const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    console.log('🔑 Auth middleware - Token present:', !!token);

    if (!token) {
        console.log('❌ No token provided');
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('✅ Token verified for user:', decoded.email);
        req.user = decoded;
        next();
    } catch (error) {
        console.log('❌ Invalid token:', error.message);
        return res.status(403).json({ message: 'Invalid or expired token.' });
    }
};

module.exports = authenticateToken;