// console.log("Hello World!");
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Config JSON response
app.use(express.json());

// Models
const User = require('./models/User');

// Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({
        msg: "Bem vindo a nossa API!"
    });
});

// Private Route
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    // Check if user exists
    const user = await User.findById(id, '-password');
    if(!user) {
        return res.status(404).json({
            msg: "Usuario nao encontrado"
        });
    }

    res.status(200).json({
        user
    });
});

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(!token) {
        return res.status(401).json({
            msg: "Acesso negado!"
        });
    }

    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret);
        next();
    } catch(error) {
        res.status(400).json({
            msg: "Token invalido"
        });
    }
}

// Register User
app.post('/auth/register', async(req, res) => {
    const {name, email, password, confirmpassword} = req.body;
    // validations
    if(!name) {
        return res.status(422).json({
            msg: 'O nome e obrigatorio!'
        });
    }
    if(!email) {
        return res.status(422).json({
            msg: 'O email e obrigatorio!'
        });
    }
    if(!password) {
        return res.status(422).json({
            msg: 'A senha e obrigatorio!'
        });
    }
    if(!confirmpassword) {
        return res.status(422).json({
            msg: 'A confirmacao da senha e obrigatorio!'
        });
    }
    if(password !== confirmpassword) {
        return res.status(422).json({
            msg: 'As senhas nao conferem!'
        });
    }

    // Check if user exists
    const userExists = await User.findOne({
        email: email
    });

    if(userExists) {
        return res.status(422).json({
            msg: 'Email ja existe, use outro email!'
        });
    }

    // Create password

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create user

    const user = new User({
        name,
        email,
        password: passwordHash,
    });

    try {
        await user.save();
        res.status(200).json({
            msg: "Usuario cadastrado com sucesso."
        });
    } catch (error) {
        console.log('Error: ' + error);
        res.status(500).json({
            msg: "Houve um erro no servidor, tente novamente mais tarde."
        });
    }
});

// Login User
app.post("/auth/login", async(req, res) => {
    const {email, password} = req.body;

    // validations
    if(!email) {
        return res.status(422).json({
            msg: 'O email e obrigatorio!'
        });
    }
    if(!password) {
        return res.status(422).json({
            msg: 'A senha e obrigatorio!'
        });
    }

    // Check if user exitsts
    const user = await User.findOne({
        email: email
    });

    if(!user) {
        return res.status(404).json({
            msg: 'Usuario nao encontrado!'
        });
    }

    // Check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if(!checkPassword) {
        return res.status(422).json({
            msg: 'Senha invalida!'
        });
    }

    try {
        const secret = process.env.SECRET;
        const token = jwt.sign({
            id: user._id,
        }, secret,);

        res.status(200).json({
            msg: "Autenticacao realizada com sucesso", token
        });
    } catch (error) {
        console.log("Error: " + error);
        res.status(500).json({
            msg: "Houve um erro no servidor, tente novamente mais tarde."
        });
    }

});


// Credenciais
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.lklclhb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
    .then(() => {
        app.listen(3030);
        console.log('Conectou ao Banco de Dados');
    })
    .catch(err => console.log('Erro ao conectar com o Banco de Dados' + err));
