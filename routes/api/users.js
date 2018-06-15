const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt  = require('jsonwebtoken');
const keys = require('../../config/keys');
const passport = require('passport');

//Load Inpuut Validation
const validateRegisterInput = require('../../validation/register');
const validateLoginInput = require('../../validation/login');

// Load User model
const User = require('../../models/User')
// @route   GET api/users/test
// @desc    Test user route
// @access  Public 
router.get('/test',(req, res) => res.json({msg: "Users Works"}));

// @route   GET api/users/register
// @desc    Register user
// @access  Public 
router.post('/register',(req, res) => {
    const {errors, isValid} = validateRegisterInput(req.body); //validate
    if(!isValid){
        return res.status(400).json(errors)
    }
    User.findOne({ email: req.body.email})
        .then(user => {
            if(user)
                return res.status(400).json({email: "Email already exist"})
            else{
                const avatar = gravatar.url(req.body.email, {
                    s: 200,  // size
                    r: 'pg', // Rating
                    d: 'mm'  // Default   
                });
                const newUser = new User({
                    name: req.body.name,
                    email: req.body.email,
                    avatar,
                    password: req.body.password,
                });
                bcrypt.genSalt(10, (err, salt) => {
                    bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if(err)
                            res.status(400).json({email: "password error"})
                        else{
                            newUser.password = hash;
                            newUser.save()
                                .then(user => res.json(user))
                                .catch(err => console.log(err));
                        }
                    });
                });
            }        
            })
});

// @route   GET api/users/login
// @desc    Login User /  Return TOKEN
// @access  Public 

router.post('/login', (req, res) => {
    const {errors, isValid} = validateLoginInput(req.body); //validate
    if(!isValid){
        return res.status(400).json(errors)
    }

    const email = req.body.email;
    const password = req.body.password;
    User.findOne({email})
        .then(userLog => {
            // Check for user
            if(!userLog){
                errors.email = 'User not found';
                return res.status(404).json(errors);
            }
            // Check password match
            bcrypt.compare(password, userLog.password)
            .then(isMatch =>{
                if(isMatch){
                    const payload = {id: userLog.id, name: userLog.name, avatar: userLog.avatar}
                    jwt.sign(
                        payload,
                        keys.secretKey,
                        { expiresIn: 3600}, 
                        (err, token) =>{
                            res.json({
                                success: 'Success Login',
                                token: 'Bearer ' + token
                            })
                        });
                }
                else {
                    errors.password = 'Failure Login';
                    return res.status(404).json(errors);
                }
            });
        })

});

// @route   GET api/users/current
// @desc    Return  current user 
// @access  Private
router.get('/current', passport.authenticate('jwt', {session: false}), (req, res) =>{
    res.json({
        id: req.user.id,
        email: req.user.email,
        name: req.user.name
    });
});
module.exports = router;