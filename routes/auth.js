const { Router } = require('express');
const { check } = require('express-validator');

const { crearUsuario, login, renewToken } = require('../controllers/auth');
const { validarCampos } = require('../middlewares/validar-campos');
const { validarJWT } = require('../middlewares/validar-jwt');

const router = Router();

router.post('/new', [
  check('nombre', 'El nombre es obligatorio').notEmpty(),
  check('email', 'El correo es obligatorio').isEmail(),
  check('password', 'La contraseña es obligatoria').notEmpty(),
  validarCampos
], crearUsuario);

router.post('/', [
  check('email', 'El correo es obligatorio').isEmail(),
  check('password', 'La contraseña es obligatoria').notEmpty(),
  validarCampos
], login);

router.get('/renew', validarJWT, renewToken);

module.exports = router;
