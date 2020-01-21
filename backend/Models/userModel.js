const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const userSchema = new Schema({
    name: {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        unique: true
    },
    password: {
        type: String,
        minlength: 6
    },
    userImage: {
        type: String
    },
},
    {
        timestamps: true
});

const User = mongoose.model('User', userSchema);
module.exports = User;