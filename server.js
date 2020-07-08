const express = require ('express');
const auth = require('express-basic-auth');
const url = require('url');
const fs = require('fs');

var authInfo;

fs.readFile('auth.json', 'utf8', function (err, data) {
  if (err) throw err;
  authInfo = JSON.parse(data);
});

var app = express()


app.get('/whitelist', (req, res) => {
    let credentials = decodeAuthorization(req.get('Authorization'))
    
    //Esto es nonsense
    if (req.query.u){
        let user = req.query.u
        if (!authInfo.users.hasOwnProperty(user) || user != credentials.user){
           res.status(401).send('Unauthorized');
           return
        }
    }//

    if (req.query.g) {
        let group = req.query.g
        if (!authInfo.groups.hasOwnProperty(group)){
            res.status(401).send('Specified group not found');
            return
        }
        let users = authInfo.groups[group]
        if (!users.includes(credentials.user)){
            res.status(401).send('User not included in the specified group');
            return
        }
    }
    if (authorize(credentials)) {
        res.status(200).send('Authorized');
    } else  res.status(401).send('Unauthorized');
});


app.get('/blacklist', function (req, res) {
    let credentials = decodeAuthorization(req.get('Authorization'))

    if (req.query.u){
        let user = req.query.u
        if (user == credentials.user){
           res.status(401).send('Unauthorized');
           return
        }
    }

    if (req.query.g) {
        let group = req.query.g
        if (!authInfo.groups.hasOwnProperty(group)){
            res.status(401).send('Specified group not found');
            return
        }
        let users = authInfo.groups[group]
        if (users.includes(credentials.user)){
            res.status(401).send('Unauthorized');
            return
        }
    }

    if (authorize(credentials)) {
        res.status(200).send('Authorized');
    } else  res.status(401).send('Unauthorized');

});

const decodeAuthorization = (authorizarion) => {
    let encodedCredentials = authorizarion.split(' ')[1]
    let decodedCredentials =  Buffer.from(encodedCredentials, 'base64').toString('ascii');
    let aux = decodedCredentials.split(':')
    let credentials = {}
    credentials.user = aux[0]
    credentials.password = aux[1]
    return credentials
}
   

const authorize = (credentials) => {
    if (authInfo.users.hasOwnProperty(credentials.user)) {
        let isPasswordCorrect = auth.safeCompare(credentials.password, authInfo.users[credentials.user])
        return  isPasswordCorrect
    }
        return false
}
  
app.listen(8080, function () {
console.log('Server listening on port 8080!');
});
  
