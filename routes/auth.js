var express = require('express');
var router = express.Router();
let authController = require('../controllers/auth');

/* GET home page. */
router.post('/register',authController.register);
router.post('/login',authController.login);
router.get('/logout', authController.logout);
router.post('/renewtokens', authController.renewTokens);


module.exports = router;
