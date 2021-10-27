// sign the directory and audit files

import fs from "fs";
import { Command } from 'commander';
import { JWK, JWS } from "node-jose";
import { DirectoryLog } from "./interfaces";
import base64url from "base64url";

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
program.requiredOption('-k, --key <key>', 'path of private key');
program.requiredOption('-f, --file <file>', 'path of file to sign');
program.requiredOption('-o, --out <out>', 'path of output signed JWS file');
program.parse(process.argv);
const options = program.opts() as Options;

const sign = async (keyPath: string, filePath: string, outPath: string) => {
    try {
        const key = JSON.parse(fs.readFileSync(keyPath).toString('utf-8')) as JWK.Key;
        if (!key) {
            throw "Can't parse key from " + keyPath;
        }
        const file = JSON.parse(fs.readFileSync(filePath).toString('utf-8')) as DirectoryLog;
        if (!file) {
            throw "Can't parse file from " + filePath;
        }
        const payload = JSON.stringify(file);
        JWS.createSign({format: "compact"}, key).
            update(payload).
            final().
            then(result => {
                const jws = result as unknown as /*Jws*/ string;
//                const jwsString = JSON.stringify(jws);
                fs.writeFileSync(outPath, /*jwsString*/ jws);
            }).
            catch(err => {
                console.log("Error signing file" + err);
            })
    } catch (err) {
        console.log("Signing error");
        console.log(err);
        return;
    }
} 

// main
void (async () => {
    sign(options.key, options.file, options.out);
})();