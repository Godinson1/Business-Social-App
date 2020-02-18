const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const userSchema = new Schema({
    name: {
        type: String,
        required: true
    },
    handle: {
        type: String,
        required: true,
        minlength: 3,
        trim: true
    },
    email: {
        type: String,
        unique: true
    },
    password: {
        type: String,
        minlength: 6,
        required: true
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