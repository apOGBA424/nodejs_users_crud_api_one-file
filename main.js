require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');



// middlewares
const app = express();
app.use(express.json());
// app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());


// variables
const port = process.env.PORT || 4000;
const jwtsecret = process.env.JWT_SECRET; //in .env file the value is: jwt-secr3t


// dummy database
const userDB = [
    {
        id: new Date().valueOf().toString()+'A',
        isPaid: true,
        name: 'John Doe',
        password: 'asdfghjkl1',
    },
    {
        id: new Date().valueOf().toString()+'B',
        isPaid: false,
        name: 'Sarah Ford',
        password: 'asdfghjkl2',
    },
    {
        id: new Date().valueOf().toString()+'C',
        isPaid: true,
        name: 'Harry Poter',
        password: 'asdfghjkl3',
    },
    {
        id: new Date().valueOf().toString()+'D',
        isPaid: false,
        name: 'Wayne Rooney',
        password: 'asdfghjkl4',
    },
    {
        id: new Date().valueOf().toString()+'E',
        isPaid: true,
        name: 'Harly Quinn',
        password: 'asdfghjkl5',
    }
]



// home route
app.get('/', (req, res)=>{
    // console.table(userDB);
    res.json(userDB);
});


// sign-up route
app.post('/signup', async(req, res)=>{
    
    try {
        const already_user = userDB.find((user_acct)=> user_acct.name === req.body.name);
        
        // check if user account exists
        if (already_user) {
            return res.status(400).send('Account taken. Choose another name.');
        }

        const newUser = {
            id : new Date().valueOf().toString(),
            isPaid: false,
            name : req.body.name,
            password : await bcrypt.hash(req.body.password, 10)
        }

        // console.log(`newUser['id']--> ${newUser['id']}`);
        // console.log(`req.body['name']--> ${req.body['name']}`);
        // console.log(`req.body['password']--> ${req.body['password']}`);

        // finally save user in database
        userDB.push(newUser);
        res.status(200).json({'msg': `${newUser.name} created`});
        
    } catch (error) {
        console.log('error occured');
    }
});


// middleware to get user_id from cookie
const authorizeUser_by_ID_fromCookie = (req, res, next)=>{

    const cookie_token = req.cookies.authorization;
    

    // error after cookie duration expired
    if (!cookie_token) {
        // return res.json({error});
        return res.status(403).json({'msg': 'Access denied'});
    }

        console.log(`cookie_token--> ${cookie_token}`);
        
        const token_from_cookie = cookie_token.split(' ')[1];
        console.log(`\ntoken_from_cookie (after split(''))--> ${token_from_cookie}`);


        try {
            jwt.verify(token_from_cookie, jwtsecret, (err, decoded_payload)=>{
                
                //error for tampered cookie
                if (err) {
                    // return res.json({err}); 
                    return res.status(401).json({'err': 'token not valid'});
                }

                /* create a user variable in request-object and name it
                "req.user" then assign to it the "decode_payload" as the value*/
                req.user = decoded_payload;

                // return res.json({'req.user': req.user});

            });
        } catch (error) {
            return res.status(500).json({'err': 'server error from authz middleware'});
        }

    next();
}



// sign-in route
app.post('/signin', async(req, res)=>{
    
    try {
        
        // user's input values
        const {name, password} = req.body;

        // authenticate user credential here
        const verified_user = userDB.find((user_acct)=> user_acct.name === name);

        if (!verified_user) {
            return res.status(401).json({'msg': 'name invalid'});
        }
        
        const password_match = await bcrypt.compare(password, verified_user.password);
        
        
        if (password_match === false) {

            return res.status(401).json({'msg': 'password not match'});

        }else{
            
            const user = {
                id : verified_user.id,
                name : verified_user.name,
            }
            
            const jwt_token = jwt.sign(user, jwtsecret);
            const authorization = `Bearer ${jwt_token}`;
            const authzHeader = req.headers['authorization'] = authorization;

            console.log(`authzHeader will save as--->  'authorization': ${authzHeader}`);

            res.cookie('authorization', authzHeader , {maxAge:55000, httpOnly: true}); //55seconds

            return res.status(202).json({'msg': `${user.name} credentials valid`,user});
        }
        
    } catch (error) {
        console.log('error occured');
    }
});


// find a single user from database
app.get('/user/:id', (req, res)=>{
    
    try {
        const user_info_find = userDB.find((user)=> user.id === req.params.id);

        if (!user_info_find) {
            return res.status(404).json({'msg': 'invalid credential'});
        }

        return res.json(user_info_find);
       
    } catch (error) {
        console.log('request failed on error')
    }
});


// edit a single user's data 
app.put('/user/payments/:id',authorizeUser_by_ID_fromCookie, (req, res)=>{

    try {
        const user_info_find = userDB.find((user)=> user.id === req.params.id);

        if (!user_info_find) {
            return res.status(404).json({'msg': 'invalid credential'});
        }

        user_info_find.isPaid = req.body.isPaid;

        return res.json({user_info_find,'req.user': req.user});

       
    } catch (error) {
        console.log();
    }
});


// remove a single user from database
app.delete('/user/remove/:id',authorizeUser_by_ID_fromCookie, async(req, res)=>{
    
    try {
        const user_info_find = userDB.find((user)=> user.id === req.params.id);
        const user_info_findIndex = userDB.findIndex((user)=> user.id === req.params.id);

        if (user_info_find.id !== req.params.id) {
            return res.status(401).json({'err': 'access denied'});
        }

        if (!user_info_find) {
            return res.status(404).json({'err': 'invalid credential'});
        }

        // delete user that matches the index using .splice( ) method
        const removeIndex_match = userDB.splice(user_info_findIndex, 1)[0];
        console.log(`${removeIndex_match.name} account delete request done.`);

        // return res.status(202).json(userDB);
        return res.send(userDB).json({'msg': `\n\n${removeIndex_match.name} account delete request done.`});

    } catch (error) {
        console.log();
    }
});


// logout user
app.delete('/logout',authorizeUser_by_ID_fromCookie, (req, res)=>{
    console.log('user account log out');
    res.clearCookie('authorization')
        .status(204).json({'msg': 'account logged out'});
});


// protected route
app.get('/dashboard',authorizeUser_by_ID_fromCookie, (req, res)=>{
    console.log('\n\n\nuser dashboard route');

    try {
    res.status(200).send(`${req.user.name} Dashboard`);
        
    } catch (error) {
        console.log('token error')
    }

});



app.listen(port, ()=>{
    console.log(`http://localhost:${port}/ running`);
});
