const express = require('express');
const path = require('path');
const fileUpload = require('express-fileupload');
const crypto = require('crypto');
const fs = require('fs');
const app = express();
const axios = require('axios');

app.set('view engine', 'ejs');
app.set('views', './views')

//Génération des clés
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const key = ec.genKeyPair();
const clePublique = key.getPublic().encode('hex');

// default options
app.use(fileUpload());

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

        const signature = key.sign(hex);
        const der = signature.toDER("hex");

        axios({
            method: 'post',
            url: 'http://localhost:9986/transaction/new',
            data: {
                "from":"046d0d88463a46c80faa88b976b60498df78ea48ffacb62d17bb98518266c175bbc073a31bcd0c80e7099272d92490a032757cb3960b9502caaa3d8f1a22a0f76a",
                "to": "" + clePublique,
                "fileHash": "" + der,
                "amount":100
            }
        }).then((response) => {
            console.log(response.data);
        }, (error) => {
            console.log(error);
        });

        fs.unlinkSync(uploadPath);

        res.send('Fichier inscrit sur la chain, votre clé publique est : ' + clePublique);
    });
});


const port = process.env.PORT || 8080;

app.get('/upload', function(req, res) {
    res.render('index')
});

app.get('/check', function(req, res){
    res.render('verify')
});

app.post('/verify', (req, res) => {

    let blocks = [];
    axios.get('http://localhost:9986/')
        .then((response) => {
            const chain = response.data;
            chain.map(x => {
                if(x['data'][0]['to']===clePublique) {
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
            res.send(result ? 'Oui' : 'Non');
        });
    });
})

app.listen(port);
console.log('Server started at http://localhost:' + port);