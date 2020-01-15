const express = require('express');
const mongoose = require('mongoose');
const config = require('config');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const port = process.env.PORT || 3000;

const uri = config.get('ATLAS_URI');
mongoose.connect(uri, { useNewUrlParser: true, useCreateIndex: true, useUnifiedTopology: true});

const connection = mongoose.connection;

connection.once('open', () => {
    console.log("Your connection to MongoDB has been established successfully..");
});

app.listen(port, () => {
    console.log(`Your Server is running on port: ${port}`);
});