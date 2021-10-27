// verify the signature of the directory and audit files

import fs from "fs";
import { Command } from 'commander';
import { JWK, JWS } from "node-jose";
import { DirectoryLog } from "./interfaces";

interface Options {
    key: string;
    file: string;
    out: string;
}

interface Jws {
    header?: any;
    payload?: any;
    protected?: any;
    signature: any;
}

const program = new Command();
program.requiredOption('-k, --key <key>', 'path of public key');
program.requiredOption('-f, --file <file>', 'path of signed JWS file');
program.requiredOption('-o, --out <out>', 'path of the ouput signature payload');
program.parse(process.argv);
const options = program.opts() as Options;

const verify = async (keyPath: string, filePath: string, outPath: string) => {
    try {
        const key = await JWK.asKey(JSON.parse(fs.readFileSync(keyPath).toString('utf-8')));// as JWK.Key;
        if (!key) {
            throw "Can't parse key from " + keyPath;
        }
        const jws = fs.readFileSync(filePath).toString('utf-8');// JSON.parse(fs.readFileSync(filePath).toString('utf-8')) as Jws;
        if (!jws) {
            throw "Can't parse file from " + filePath;
        }
        //const jwsString = JSON.stringify(file);
        JWS.createVerify(key).
            verify(jws).
            then(result => {
                const directory = (result as unknown as Jws).payload.toString('utf-8');
                fs.writeFileSync(outPath, directory);
            }).
            catch(err => {
                console.log("Error verifying file" + err);
            })


    } catch (err) {
        console.log("Verification error");
        console.log(err);
        return;
    }
} 

// main
void (async () => {
    verify(options.key, options.file, options.out);
})();