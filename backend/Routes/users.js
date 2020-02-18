const User = require('../Models/userModel');
const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

//To Register a User

router.route('/register').post((req, res) => {
    const { name, handle, email, password } = req.body;

    if(!name || !email || !handle || !password) return res.status(400).json({ message: "Please fill all details" });
    
    User.findOne({handle})
        .then(user => {
            if(user) return res.status(400).json({ 
                message: `Hey User with @${handle} already exist.. Choose another handle` });
        })

    const newUser = new User({
        name,
        handle,
        email,
        password
    });

    bcrypt.genSalt(10, (error, salt) => {
        bcrypt.hash(newUser.password, salt, (error, hash) => {
            if(error) throw error;
            newUser.password = hash;
            newUser.save()
                .then(user => {
                    jwt.sign(
                        {id: user._id, handle: user.handle},
                        config.get('Jwt_Secret'),
                        {expiresIn: 3600},
                        (error, token) => {
                            if (error) throw error;
                            res.json({
                                token,
                                user: {
                                    name: user.name,
                                    handle: user.handle,
                                    email: user.email
                                }
                            })
                        }
                    )
                })
        })
        .catch(err => {
            console.error(err);
            return res.status(500).json({ message: "Something went wrong!" });
        });
    })   
});


//To Logon a User

router.route('/login').post((req, res) => {
    const { email, password } = req.body;

    if(!email || !password) return res.status(400).json({ message: "Please fill all details" });
    
    User.findOne({email})
        .then(user => {
            if(!user) return res.status(400).json({ 
                message: `Hey User with @${email} does not exist.. ` });

    bcrypt.compare(password, user.password)
        .then(isMatched => {
            if (!isMatched) return res.status(400).json({ message: "Invalid credentials.. Try again!" });

                    jwt.sign(
                        {id: user._id, handle: user.handle},
                        config.get('Jwt_Secret'),
                        {expiresIn: 3600},
                        (error, token) => {
                            if (error) throw error;
                            res.json({
                                token,
                                user: {
                                    name: user.name,
                                    handle: user.handle,
                                    email: user.email
                                }
                            })
                        }
                    )
                })
        })
        .catch(err => {
            console.log(err);
            return res.status(500).json({ message: "Something went wrong!" });
        })        

})

module.exports = router;