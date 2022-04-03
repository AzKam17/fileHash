const express = require('express');
const path = require('path');
const fileUpload = require('express-fileupload');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const app = express();
const axios = require('axios');
const API = process.env.API || 'http://localhost:9986';
console.log(API);

app.set('view engine', 'ejs');
app.set('views', './views');
app.use(express.static('./public'));

let clesParNavigateur = {};
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

// default options
app.use(fileUpload());
app.use(cookieParser());

const getKeys = (cookie) => {
    //Génération des clés
    let key = ec.genKeyPair();
    return [key, key.getPublic().encode('hex')];
}

const randomStr = (length) => {
    let result           = '';
    let characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let charactersLength = characters.length;
    for ( let i = 0; i < length; i++ ) {
        result += characters.charAt(Math.floor(Math.random() *
            charactersLength));
    }
    return result;
}

app.post('/upload', function(req, res) {
    let sampleFile;
    let uploadPath;

    if (!req.files || Object.keys(req.files).length === 0) {
        return res.status(400).send('No files were uploaded.');
    }

    // The name of the input field (i.e. "sampleFile") is used to retrieve the uploaded file
    sampleFile = req.files.sampleFile;
    uploadPath = __dirname + '/uploads/' + sampleFile.name;

    // Use the mv() method to place the file somewhere on your server
    sampleFile.mv(uploadPath, function(err) {
        if (err)
            return res.status(500).send(err);


        const fileBuffer = fs.readFileSync(uploadPath);
        const hashSum = crypto.createHash('sha256');
        hashSum.update(fileBuffer);
        const hex = hashSum.digest('hex');

        const signature = clesParNavigateur[req.cookies.keys][0].sign(hex);
        const der = signature.toDER("hex");

        axios({
            method: 'post',
            url: API + '/transaction/new',
            data: {
                "from":"046d0d88463a46c80faa88b976b60498df78ea48ffacb62d17bb98518266c175bbc073a31bcd0c80e7099272d92490a032757cb3960b9502caaa3d8f1a22a0f76a",
                "to": "" + clesParNavigateur[req.cookies.keys][1],
                "fileHash": "" + der,
                "amount":100
            }
        }).then((response) => {
            console.log(response.data);
        }, (error) => {
            console.log(error);
        });

        fs.unlinkSync(uploadPath);

        res.render('sended', {
            clePub: clesParNavigateur[req.cookies.keys][1]
        });
    });
});

const port = process.env.PORT || 8080;

app.get('/', function(req, res) {
    let cookies = req.cookies.keys;
    if(cookies === undefined || clesParNavigateur[cookies] === undefined){
        console.log("Pas de clés, on génère de nouvelles clés");
        cookies = randomStr(15);
        res.cookie("keys", cookies);
        clesParNavigateur['' + cookies] = getKeys(cookies);
        console.log(getKeys(cookies));
    }

    res.render('index', {
        clePub: clesParNavigateur[cookies][1]
    })
});

app.get('/check', function(req, res){
    res.render('verify')
});

app.post('/verify', (req, res) => {

    let blocks = [];
    axios.get(API + '/')
        .then((response) => {
            const chain = response.data;
            chain.map(x => {
                if(x['data'][0]['to']=== req.body.clePublique) {
                    blocks.push(x['data'][0])
                }
            });
            console.log(blocks)
        });

    let sampleFile;
    let uploadPath;

    if (!req.files || Object.keys(req.files).length === 0) {
        return res.status(400).send('No files were uploaded.');
    }

    // The name of the input field (i.e. "sampleFile") is used to retrieve the uploaded file
    sampleFile = req.files.sampleFile;
    uploadPath = __dirname + '/uploads/' + sampleFile.name;

    // Use the mv() method to place the file somewhere on your server
    sampleFile.mv(uploadPath, function(err) {
        if (err)
            return res.status(500).send(err);

        // Use the mv() method to place the file somewhere on your server
        sampleFile.mv(uploadPath, function(err) {
            if (err)
                return res.status(500).send(err);


            const fileBuffer = fs.readFileSync(uploadPath);
            const hashSum = crypto.createHash('sha256');
            hashSum.update(fileBuffer);
            const hex = hashSum.digest('hex');

            let cleImporte = ec.keyFromPublic(req.body.clePublique, 'hex');
            let result = false;
            blocks.map(x => {
                result |= cleImporte.verify(hex, x['signature'])
            });

            fs.unlinkSync(uploadPath);
            res.render('result', {
                msg: result ? " a bien été émis par le propriétaire de la clé publique fournie" : ' ne provient pas du propriétaire de la clé publique'
            });
        });
    });
})

app.get('/blockchain', (req, res) => {
    axios.get(API)
        .then((response) => {
            const chain = response.data;
            res.render('blockchain', {
                blocks: chain
            });
        });
});

app.listen(port);
console.log('Server started at http://localhost:' + port);