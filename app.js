/* imports */
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// Config JSON response
app.use(express.json());

const checkToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ msg: "Acesso negado!" });
  }

  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);
    next();
  } catch (err) {
    res.status(400).json({
      msg: "Token inválido!",
    });
  }
};

const getUserId = (req) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  const secret = process.env.SECRET;
  const decoded = jwt.verify(token, secret);

  return decoded.id;
};

// -------- Rota Privada

// Exibir Usuário
app.get("/usuario", checkToken, async (req, res) => {
  const id = getUserId(req);

  try {
    const usuario = await Usuario.findById(id, "-senha");
    res.status(200).json(usuario);
  } catch (err) {
    res.status(400).json({
      msg: "Usuário não encontrado!",
    });
  }
});

// Exibir Receita

app.get("/receitas", checkToken, async (req, res) => {
  const id = getUserId(req);

  try {
    const usuario = await Usuario.findById(id, "-senha");
    const receitas = usuario.receitas;
    res.status(200).json(receitas);
  } catch (err) {
    res.status(400).json({
      msg: "Usuário não encontrado!",
    });
  }
});

// Salvar Receita

app.post("/receitas", checkToken, async (req, res) => {
  const id = getUserId(req);
  const {
    titulo,
    tempo_de_preparo,
    instrumentos_utilizados,
    ingredientes,
    receita,
  } = req.body;

  if (
    !titulo ||
    !tempo_de_preparo ||
    !instrumentos_utilizados ||
    !ingredientes ||
    !receita.length
  ) {
    return res.status(422).json({
      msg: "Houve um erro na hora de salvar a receita!",
    });
  }

  const usuario = await Usuario.findById(id, "-senha");

  const body = {
    _id: new mongoose.Types.ObjectId(),
    titulo,
    tempo_de_preparo,
    instrumentos_utilizados,
    ingredientes,
    receita,
  };

  try {
    await usuario.receitas.push(body);
    await usuario.save();
    res.status(200).json({
      msg: "Receita salva com sucesso!",
    });
  } catch (err) {
    res.status(400).json({
      msg: "Houve um erro na hora de salvar a receita!",
    });
  }
});

// Excluir Receita

app.delete("/receitas/:idReceita", checkToken, async (req, res) => {
  const id = getUserId(req);
  const { idReceita } = req.params;

  try {
    await Usuario.findByIdAndUpdate(
      id,
      { $pull: { receitas: { _id: new mongoose.Types.ObjectId(idReceita) } } },
      { new: true, multi: true }
    );
    res.status(200).json({
      msg: "Receita apagada com sucesso!",
    });
  } catch (err) {
    console.log(err);
    res.status(400).json({
      msg: "Falha na remoção da receita!",
    });
  }
});

// -------- Rota Pública
app.get("/", (req, res) => {
  res.status(200).json({
    msg: "Bem-vindo à nossa API!",
  });
});

// Models
const Usuario = require("./models/Usuario");

// Registro de Usuário
app.post("/auth/registro", async (req, res) => {
  const { nome, email, senha, confirmSenha } = req.body;

  // Validações
  if (!nome) {
    return res.status(422).json({
      msg: "O nome é obrigatório!",
    });
  }

  if (!email) {
    return res.status(422).json({
      msg: "O e-mail é obrigatório!",
    });
  }

  if (!senha) {
    return res.status(422).json({
      msg: "A senha é obrigatória!",
    });
  }

  if (senha !== confirmSenha) {
    return res.status(422).json({
      msg: "As senhas são diferentes!",
    });
  }

  // Checar se o usuário já existe
  const userExists = await Usuario.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({
      msg: "O e-mail já foi utilizado!",
    });
  }

  // Criação de senha
  const salt = await bcrypt.genSalt(12);
  const senhaHash = await bcrypt.hash(senha, salt);

  // Criação de usuário
  const usuario = new Usuario({
    nome,
    email,
    senha: senhaHash,
  });

  try {
    await usuario.save();

    res.status(201).json({
      msg: "Usuário criado com sucesso!",
    });
  } catch (err) {
    console.log(err);
    res
      .status(500)
      .json({ msg: "Erro no servidor, tente novamente mais tarde!" });
  }
});

// Login Usuário
app.post("/auth/login", async (req, res) => {
  const { email, senha } = req.body;

  // Validações

  if (!email) {
    return res.status(422).json({
      msg: "O e-mail é obrigatório!",
    });
  }

  if (!senha) {
    return res.status(422).json({
      msg: "A senha é obrigatória!",
    });
  }

  // Checar se usuário existe

  const usuario = await Usuario.findOne({ email: email });

  if (!usuario) {
    return res.status(422).json({
      msg: "Usuário não encontrado!",
    });
  }

  // Checar se senha bate
  const checkSenha = await bcrypt.compare(senha, usuario.senha);

  if (!checkSenha) {
    return res.status(422).json({
      msg: "Senha incorreta!",
    });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: usuario._id,
      },
      secret
    );

    res.status(200).json({ msg: "Usuário logado com sucesso!", token });
  } catch (err) {
    console.log(err);
    res
      .status(500)
      .json({ msg: "Erro no servidor, tente novamente mais tarde!" });
  }
});

// Credenciais
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPass}@cluster0.nzp0ke3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`
  )
  .then(() => {
    app.listen(3000);
    console.log("Conectou ao banco!");
  })
  .catch((err) => console.log(err));
