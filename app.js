
require('dotenv').config();             //there is no need of defining it with const as it will automatically configures in the file
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;           //using oauth 2.0 as passport strategy
const findOrCreate = require('mongoose-findorcreate');
 
const app = express();;

app.use(express.static('public'));
app.set('view engine' , 'ejs');
app.use(bodyParser.urlencoded({extended: true}));


//---------------------------PASSPORT----------------------------

//-------------Initial configuration------------

app.use(session({
    secret : "Just a secret",               //This is the secret used to sign the session ID cookie. This can be either a string for a single secret, or an array of multiple secrets.
    resave : false,                         //Forces the session to be saved back to the session store, even if the session was never modified during the request.
    saveUninitialized : false               //Forces a session that is "uninitialized" to be saved to the store. A session is uninitialized when it is new but not modified.
})) 

app.use(passport.initialize());             //for using passport
app.use(passport.session());                //use passport for dealing with sessions


//-----------------------------------MONGOOSE----------------------------

mongoose.connect("mongodb://localhost:27017/userDB" , {useUnifiedTopology: true, useNewUrlParser: true});

mongoose.set("useCreateIndex" , true);          //for removing deprecated warning (collection.ensureIndex is deprecated. Use createIndexes instead.)

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId : String,                                   //google id will be generated after registering and will be same for that particluar profile
    secret : String                                      //secret will be attached with a user
})


//-----------------PLUGINS-------------

userSchema.plugin(passportLocalMongoose);               //using passportlocalmongoose in userSchema, it will help us to salt and hash passwords and save in database
userSchema.plugin(findOrCreate);                        //as findorcreate is not a function we need to plug in explicitly

const User = new mongoose.model("User" , userSchema);


//---------------------PASSPORT----------------

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());                  //stuffing the data into cookie
// passport.deserializeUser(User.deserializeUser());              //destriying the cokkie and using the data inside of it


passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

  
passport.use(new GoogleStrategy({                                               //copy from documentation for using googlestrategy
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {                    //google sends back accesstoken to allow users to take data, getting profile
    User.findOrCreate({ googleId: profile.id }, function (err, user) {      
      return cb(err, user);
    });
  }
));

//------------------GET-----------------------------

app.get("/" , function(req , res)
{
    res.render("home");
})

app.get("/auth/google" ,passport.authenticate("google" , {scope : ["profile"] }))                //authenticate using google strategy , what we want back is profile id

app.get("/auth/google/secrets", passport.authenticate('google', { failureRedirect: '/login' }),function(req, res)               //Authenticating a user locally after logging in using google if a user fails to authorize redirect to login page
{
    res.redirect('/secrets');                                      // Successful authentication, redirect secrets.
});

app.get("/login" , function(req , res)
{
    res.render("login");
})

app.get("/register" , function(req , res)
{
    res.render("register");
})

app.get("/secrets" , function(req , res)
{
    // if(req.isAuthenticated())                     //if the user is authenticated i.e there session is running then render secrets page else redirect to login page
    // {
    //     res.render("secrets")
    // }
    // else
    // {
    //     res.redirect("/login");
    // }
    User.find({"secret" : {$ne : null}} , function(err , foundUser)         //find user where secret is not null
    {
        if(err)
        {
            console.log(err);
        }
        else
        {
            if(foundUser)
            {
                res.render("secrets" , {usersWithSecrets : foundUser})          //pass the user into secrets
            }
        }
    })
})

app.get("/submit" , function(req , res)
{
    if(req.isAuthenticated())
    {
        res.render("submit")
    }
    else
    {
        res.redirect("login")
    }
})

app.get("/logout" , function(req , res)
{
    req.logout()                                //logging out of the session
    res.redirect("/")
})


//------------------POST---------------------------

app.post("/register" , function(req , res)
{
    User.register({username : req.body.username} , req.body.password , function(err , user)                //registering a new user
    {
        if(err)
        {
            console.log(err)
            res.redirect("/register")
        }
        else
        {
            passport.authenticate("local")(req , res , function()                   //Authentication , use the local strategy for authentication
            {
                res.redirect("/secrets");                       //if a user is logged in which means session is running then display the secrets page
            })
        }
    })
})

app.post("/login" , function(req,res)
{
   const newUser = new User({
       username : req.body.username,
       password : req.body.password
    })

    req.login(newUser , function(err)
    {
        if(err)
        {
            console.log(err);
        }
        else
        {
            passport.authenticate("local")(req , res , function()
            {
                res.redirect("/secrets")
            })
        }
    })
})

app.post("/submit" , function(req , res)
{
    const submittedSecret = req.body.secret;                    //secret entered by user

    User.findById(req.user.id , function(err , foundUser)           //find user
    {
        if(err)
        {
            console.log(err);
        }
        else
        {
            if(foundUser)
            {
                foundUser.secret = submittedSecret;             //assign secret to user

                foundUser.save(function()                       //save that user in database
                {
                    res.redirect("/secrets")
                });
            }
        }
    })
})

app.listen(3000 , function()
{
    console.log("Server started on port 3000");
})