const express = require('express');
const router = express.Router();
const connectToDatabase = require('../models/db');
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const logger = require('../logger');
const dotenv = require('dotenv');
dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async (req, res) => {
    try {
        const db = await connectToDatabase();
        const collection = db.collection("users");   
        const existingEmail = await collection.findOne({ email: req.body.email });

        if (existingEmail) {
            logger.error('Email id already exists');
            return res.status(400).json({ error: 'Email id already exists' });
        }        

        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });


        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };
        
        const authtoken = jwt.sign(payload, JWT_SECRET);

        logger.info('User registered successfully');

        res.json({ authtoken,email });
    } catch (e) {
        console.log(e)
         return res.status(500).send('Internal server error');
    }
});

    //Login Endpoint
    router.post('/login', async (req, res) => {
        console.log("\n\n Inside login")
        try {
            // connect to `secondChance` in MongoDB through `connectToDatabase`
            const db = await connectToDatabase();
            //Access MongoDB `users` collection
            const collection = db.collection("users");
            //Check for user credentials in database
            const theUser = await collection.findOne({ email: req.body.email });
            //Check if the password matches
            if (theUser) {
                let result = await bcryptjs.compare(req.body.password, theUser.password)
                //send appropriate message if mismatch
                if(!result) {
                    logger.error('Passwords do not match');
                    return res.status(404).json({ error: 'Wrong pasword' });
                }
                //Fetch user details
                let payload = {
                    user: {
                        id: theUser._id.toString(),
                    },
                };
                const userName = theUser.firstName;
                const userEmail = theUser.email;
                //Create JWT authentication if passwords match
                const authtoken = jwt.sign(payload, JWT_SECRET);
                logger.info('User logged in successfully');
                return res.status(200).json({ authtoken, userName, userEmail });
            //Send appropriate message if user not found
            } else {
                logger.error('User not found');
                return res.status(404).json({ error: 'User not found' });
            }
        } catch (e) {
            logger.error(e);
            return res.status(500).json({ error: 'Internal server error', details: e.message });
          }
    });
    

module.exports = router