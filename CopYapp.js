//jshint esversion:6
require('dotenv').config();             //there is no need of defining it with const as it will automatically configures in the file
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');          //As we will be using md5 hashing
// const md5 = require('md5');                          //as we will be using  bcrypt
const bcrypt = require('bcrypt');
const saltRounds = 10;                                  //more the saltround more time the computer will take to create a hash


const app = express();;

app.use(express.static('public'));
app.set('view engine' , 'ejs');
app.use(bodyParser.urlencoded({extended: true}));


//-----------------------------------MONGOOSE----------------------------

mongoose.connect("mongodb://localhost:27017/userDB" , {useUnifiedTopology: true, useNewUrlParser: true});

const userSchema = new mongoose.Schema({
    email: String,
    password: String
})

//---------------------Encryption--------------------------------

// const secret = "Just a secret.";                    //this will be used to encrypt credentials

// userSchema.plugin(encrypt , {secret : process.env.SECRET , encryptedFields : ["password"] });   (Bcoz of md5)   //excludeFromEncryption:  ["email"] for excluding a particular field , but as there are only two fields so no need of this, this must be before mongoose model as model is using schema and we want to encrypt its field first

const userModel = new mongoose.model("User" , userSchema);

//------------------GET-----------------------------

app.get("/" , function(req , res)
{
    res.render("home");
})

app.get("/login" , function(req , res)
{
    res.render("login");
})

app.get("/register" , function(req , res)
{
    res.render("register");
})


//------------------POST---------------------------

app.post("/register" , function(req , res)
{
    bcrypt.hash(req.body.password , saltRounds , function(err , hash)
    {
        const newUser = new userModel({
            email : req.body.username,
            // password : md5(req.body.password)                     //tranforming the password into hash using md5 hashing
            password : hash
        })
    
        newUser.save(function(err)                          //encrypt the password field at this point
        {
            if(err)
            {
                console.log(err);
            }
            else
            {
                res.render("secrets")
            }
        })
    });

    
})

app.post("/login" , function(req,res)
{
    const username = req.body.username
    const password = req.body.password                   //output of both the pwd will be compared and as we are also tranforming this password it will be same as original pwd if entered pwd is correct

    userModel.findOne({email : username} , function(err , founduser)                 //decrypt the password field at this point
    {
        if(!err)
        {
            // if(founduser.password == password)
            // {
            //     res.render("secrets")
            // }
            if(founduser)
            {
                bcrypt.compare(password , founduser.password , function(err , result)       //compare password with founduser.password(hash) and if it is true give result
                {
                    if(result == true)
                    {
                        res.render("secrets")
                    }
                    else
                    {
                        console.log("Wrong password");
                    }
                });
            }
        }
        else
        {
            console.log(err);
        }
    })
})



app.listen(3000 , function()
{
    console.log("Server started on port 3000");
})