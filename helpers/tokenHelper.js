const jwt = require('jsonwebtoken');

let db = require("../database/db.json");


const createAuthTokens = async ({ user, secret, secret2 }) => {
    const token = jwt.sign(user, secret, { expiresIn: '10m', },);
    const refreshToken = jwt.sign(user, secret2, { expiresIn: '1y' },);
    return Promise.all([token, refreshToken]);
}

const verifyXXtoken = async (req, res, next) => {
    const token = req.header('auth-token');
    // console.log(token)
    if (!token) return res.status(401).send({ message: "something went wrong :(" });
    try {
        const {id, username} = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        let savedUser = db.users.find(user => user.username === username);
        req.user = savedUser;
        next();
    } catch (error) {
        console.log(error);
        return res.status(401).send({ message: "unathoried access" });
    }
}


module.exports.verifyXXtoken = verifyXXtoken;
module.exports.createAuthTokens = createAuthTokens;
