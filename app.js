require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()


//Enable Express Json
app.use(express.json())

//Models
const User = require('./models/User')

//Credentials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS


const dbConnection = `mongodb+srv://${dbUser}:${dbPassword}@cluster0.sb5dmxb.mongodb.net/?retryWrites=true&w=majority`

//Public Route
app.get('/', (req, res) => {
    res.status(200).json({message:"OK"})
})


const checkToken = (req, res, next) => {
    
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
       return res.status(401).json({message: "Not allowed"}) 
    }
    
    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()
    } catch (error) {
        res.status(400).json({message: "Error"})
    }

}

//private route
app.get('/user/:id', checkToken, async(req, res) => {

   const id = req.params.id 

   console.log(id)

   const user = await User.findById(id, '-password')

   console.log(user)

   if (!user){
      return res.status(404).json({message: "Error"})
   }

   res.status(200).json({ user })
})

//User register
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmPassword} = req.body   
    console.log(req.body)

    //Validations
    if(!name){
        return res.status(422).json({message: "Field name can't be empty"})
    }

    if(!email){
        return res.status(422).json({message: "Field email can't be empty"})
    }

    if(!password){
        return res.status(422).json({message: "Field password can't be empty"})
    }

    if(password !== confirmPassword){
        return res.status(422).json({message: "Passwords don't match"})
    }

    //check if email already exists in database
    const userExists = await User.findOne({ email: email })

    if (userExists){
        return res.status(422).json({message: "Email already in use"})
    }
    
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    const user = new User ({
        name, 
        email, 
        password: passwordHash
    })

    try {
        await user.save()
        return  res.status(201).json({message: "User created sucessfully!"})

    } catch (error){
        return res.status(500).json({message: "An error as occurred on server side"})
    }

})

app.post('/auth/user', async (req, res) => {
    
    const {email, password} = req.body

    if(!email){
        return res.status(422).json({message: "Field email can't be empty"})
    }

    if(!password){
        return res.status(404).json({message: "Field password can't be empty"})
    }

     //check if email already exists in database
     const user = await User.findOne({ email: email })

     if (!user){
         return res.status(422).json({message: "Not found"})
     }

     //check password match
     const checkPassword = await bcrypt.compare(password, user.password)

     if(!checkPassword){
        return res.status(422).json({message: "An error has occurred"})
     }

     try {
        const secret = process.env.SECRET
        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        )

        res.status(200).json({token})

     } catch (error){
        return res.status(500).json({message: "An error as occurred on server side"})
    }
})

//DB_Connection
mongoose.connect(dbConnection)
    .then(() => {
        app.listen(3000)
        console.log("Conected in DB")
    })
    .catch(err => console.log(err))

