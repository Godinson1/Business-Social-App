const User = require('../Models/userModel');
const router = require('express').Router();


router.route('/register').post((req, res) => {
    const { name, username, email, password } = req.body;

    if(!name || !email || !username || !password) return res.status(400).json({ message: "Please fill all details" });

    const newUser = new User({
        name,
        username,
        email,
        password
    });

    newUser.save()
        .then(user => res.json(user))
        .catch(err => {
            console.log(err);
            return res.status(500).json({ message: "Something went wrong!" });
        });
});

module.exports = router;