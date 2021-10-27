// generate key pair for signing the directory and audit files
import fs from "fs";
import { Command } from 'commander';
import { JWK } from "node-jose";

interface Options {
    publicKeyPath: string;
    privateKeyPath: string;
}

const program = new Command();
program.option('-s, --privateKeyPath <privateKeyPath>', 'private key path');
program.option('-p, --publicKeyPath <publicKeyPath>', 'public key path');
program.parse(process.argv);
const options = program.opts() as Options;

const generateKeys = async (publicKeyPath: string, privateKeyPath: string) => {
    const keyStore = JWK.createKeyStore();
    try {
        // generate signing key pair
        const key = await keyStore.generate("EC","P-256",{ use: "sig", alg: "ES256" });
        // store private key
        const privateKey = JSON.stringify(key.toJSON(true));
        fs.writeFileSync(privateKeyPath, privateKey);

        // store private key
        const publicKey = JSON.stringify(key.toJSON(false));
        fs.writeFileSync(publicKeyPath, publicKey);
        
        console.log(key);
    } catch (err) {
        console.log("Key pair generation error");
        console.log(err);
        return;
    }
} 

// main
void (async () => {
    generateKeys(options.publicKeyPath,options.privateKeyPath);
})();