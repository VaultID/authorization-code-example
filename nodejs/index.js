const express = require("express")
const path = require('path')
const app = express()
const crypto = require('crypto')
const session = require('express-session')
const axios = require('axios');

app.set('trust proxy', 1) // trust first proxy
app.use(session({
  secret: 'mysecret123',
  resave: true,
  saveUninitialized: true,
  cookie: { maxAge: 60000 }
}))

var PORT = process.env.port || 3000

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.set("views", path.join(__dirname))
app.set("view engine", "ejs")


const applicationId = '<SEU CLIENTID>'
const applicationSecret = '<SEU CLIENTID>'
const urlPSC = 'https://apicloudid.hom.vaultid.com.br'
const urlCallback = 'http://localhost:3000/callback'


app.get("/", function (req, res) {
  res.render("form", {});
})

app.get('/callback', function (req, res) {
  let state = req.query.state;
  let code = req.query.code;

  if (!req.session?.[state]) {
    return res.status(401).json({ 'message': 'State not found' });
  }

  let codes = req.session?.[state];

  const params = {
    grant_type: 'authorization_code',
    client_id: applicationId,
    client_secret: applicationSecret,
    code: code,
    code_verifier: codes.codeVerifier,
    redirect_uri: urlCallback
  }

  axios.post(`${urlPSC}/oauth`, params)
    .then(function (resp) {

      res.status(200).json(resp.data);
    }).catch(function (err) {
      console.log('Failed to exchange code', err);
      res.status(400).json('Failed to exchange code');
    });
});

app.post('/authenticate', function (req, res) {

  let username = req.body.username || '';

  let codeVerifier = createRandom();
  let codeChallenge = createCodeChallenge(codeVerifier);
  let stateIndex = crypto.randomBytes(32).toString('hex');

  req.session[stateIndex] = {
    codeVerifier: codeVerifier,
    codeChallenge: createCodeChallenge(codeChallenge)
  };

  req.session.save(() => { });

  let params = {
    'integration': 'true',
    'response_type': 'code',
    'client_id': applicationId,
    'code_challenge': codeChallenge,
    'code_challenge_method': 'S256', //S256 or plain
    'redirect_uri': urlCallback,
    'state': stateIndex,
    'scope': 'signature_session', //Optional param
    'login_hint': username, //Optional param (CPF/CNPJ)
    'lifetime': 999900,
  }

  let url = new URLSearchParams(params).toString();
  url = urlPSC.trimEnd() + '/oauth/authorize?' + url;

  res.writeHead(301, { Location: url });
  res.end();
});


function base64ToBase64Url(base64) {
  return base64.replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function createRandom() {
  let random = crypto.randomBytes(32).toString('base64');
  return base64ToBase64Url(random);
}

function createCodeChallenge(codeVerifier) {
  const randomArray = new Uint8Array(codeVerifier.length);
  for (let i = 0; i < codeVerifier.length; i++) {
    randomArray[i] = codeVerifier.charCodeAt(i);
  }

  let codeChallenge = crypto
    .createHash("sha256")
    .update(randomArray, "binary")
    .digest("base64");

  return base64ToBase64Url(codeChallenge);
}

app.listen(PORT, function (error) {
  if (error) throw error
  console.log("Server created Successfully on PORT", PORT)
})