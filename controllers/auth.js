const { response } = require('express');
const bcrypt = require('bcryptjs');

const Usuario = require('../models/usuario');
const { generarJWT } = require('../helpers/jwt');

const crearUsuario = async (req, res = response) => {
  const { email, password } = req.body;

  try {
    const existeEmail = await Usuario.findOne({ email });

    if (existeEmail) {
      return res.status(400).json({
        ok: false,
        msg: 'El correo ya está registrado', 
      })
    }

    const usuario = new Usuario(req.body);

    // Encriptar contraseña
    const salt = await bcrypt.genSalt();
    usuario.password = bcrypt.hashSync(password, salt);

    await usuario.save();

    // Generar mi JWT
    const token = await generarJWT(usuario.id);
  
    res.json({
      ok: true,
      usuario,
      token,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      ok: false,
      msg: 'Hable con el administrador',
    })
  }
}

const login = async (req, res = response) => {
  const { email, password } = req.body;
  try {
    const usuarioDB = await Usuario.findOne({ email });

    if (!usuarioDB) {
      return res.status(404).json({
        ok: false,
        msg: 'Email no encontrado',
      });
    }

    const isValidPassword = await bcrypt.compare(password, usuarioDB.password);
    console.log(isValidPassword);
    if (!isValidPassword) {
      return res.status(400).json({
        ok: false,
        msg: 'Contraseña invalida',
      });
    }

    // Generar el JWT
    const token = await generarJWT(usuarioDB.id);

    res.json({
      ok: true,
      usuario: usuarioDB,
      token,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      ok: false,
      msg: 'Hable con el administrador',
    })
  }
}

const renewToken = async (req, res) => {
  const { uid } = req;

  try {
    const usuarioDB = await Usuario.findById(uid);

    if (!usuarioDB) {
      return res.status(404).json({
        ok: false,
        msg: 'Usuario no encontrado',
      });
    }
  
    const newToken = generarJWT(uid);
  
    res.json({
      ok: true,
      usuario: usuarioDB,
      token: newToken,
    })
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      ok: false,
      msg: 'Hable con el administrador',
    })
  }
}

module.exports = {
  crearUsuario,
  login,
  renewToken,
}
