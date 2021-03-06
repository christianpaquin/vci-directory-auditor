// Audit script for the VCI issuers directory

import { Command } from 'commander';
import got from 'got';
import fs from 'fs';
import path from 'path';
import date from 'date-and-time';
import Url from 'url-parse';
import { AuditLog, CRL, DirectoryLog, IssuerKey, IssuerKids, IssuerLogInfo, TrustedIssuers } from './interfaces';
import { auditTlsDetails, getDefaultTlsDetails } from './bcp195';

const VCI_ISSUERS_DIR_URL = "https://raw.githubusercontent.com/the-commons-project/vci-directory/main/vci-issuers.json";

interface KeySet {
    keys : IssuerKey[]
}

interface Options {
    inlog: string;
    outlog: string;
    previous: string;
    auditlog: string;
    directory: string;
    test: boolean;
    verbose: boolean;
}

//
// program options
//
const program = new Command();
program.option('-i, --inlog <inlog>', 'input log file storing directory issuer keys and TLS details; if unspecified, the directory will be downloaded from the specified location');
program.option('-o, --outlog <outlog>', 'output log file storing directory issuer keys and TLS details');
program.option('-p, --previous <previous>', 'directory log file from a previous audit, for audit comparison');
program.option('-a, --auditlog <auditlog>', 'output audit file on the directory');
program.option('-d, --directory <directory>', 'URL of the directory to audit; uses the VCI one by default');
program.option('-t, --test', 'test mode');
program.option('-v, --verbose', 'verbose mode');
program.parse(process.argv);
const currentTime = new Date();
const outputUTC = true;

// process options
const options = program.opts() as Options;
if (!options.directory) {
    options.directory = VCI_ISSUERS_DIR_URL;
}
if (!options.outlog) {
    options.outlog = path.join('logs', `directory_log_${date.format(currentTime, 'YYYY-MM-DD-HHmmss', outputUTC)}.json`);
}
if (!options.auditlog) {
    options.auditlog = path.join('logs', `audit_log_${date.format(currentTime, 'YYYY-MM-DD-HHmmss', outputUTC)}.json`);
}

// download the specified directory
async function fetchDirectory(directoryUrl: string, verbose: boolean = false) : Promise<DirectoryLog> {
    const response = await got(directoryUrl, { timeout: 5000 });
    if (!response) {
        Promise.reject("Can't connect to directory");
    }

    const issuers = JSON.parse(response.body) as TrustedIssuers;
    if (!issuers) {
        Promise.reject("Can't parse issuer directory");
    }

    const issuerLogInfoArray: IssuerLogInfo[] = [];
    console.log("Directory count: " + issuers.participating_issuers.length);
    for (const issuer of issuers.participating_issuers) {
        const jwkURL = issuer.iss + '/.well-known/jwks.json';
        const issuerLogInfo: IssuerLogInfo = {
            issuer: issuer,
            keys: [],
            tlsDetails: undefined,
            crls: [],
            errors: []
        }
        const requestedOrigin = 'https://example.org'; // request bogus origin to test CORS response
        try {
            if (verbose) console.log("fetching jwks at " + jwkURL);
            const response = await got(jwkURL, { headers: { Origin: requestedOrigin }, timeout:5000 });
            if (!response) {
                throw "Can't reach JWK set URL: " + jwkURL;
            }
            const acaoHeader = response.headers['access-control-allow-origin'];
            if (!acaoHeader) {
                issuerLogInfo.errors?.push("Issuer key endpoint does not contain a CORS 'access-control-allow-origin' header");
            } else if (acaoHeader !== '*' && acaoHeader !== requestedOrigin) {
                issuerLogInfo.errors?.push(`Issuer key endpoint's CORS 'access-control-allow-origin' header ${acaoHeader} does not match the requested origin`);
            }
            const keySet = JSON.parse(response.body) as KeySet;
            if (!keySet) {
                issuerLogInfo.errors?.push("Failed to parse JSON KeySet schema");
            }
            // TODO: try to import keys to check for failures
            issuerLogInfo.keys = keySet.keys;
        } catch (err) {
            issuerLogInfo.errors?.push((err as Error).toString());
        }
        try {
            issuerLogInfo.tlsDetails = getDefaultTlsDetails(new Url(issuer.iss).hostname);
            if (issuerLogInfo.tlsDetails) {
                auditTlsDetails(issuerLogInfo.tlsDetails).map(a => issuerLogInfo.errors?.push(a));
            }
        } catch (err) {
            issuerLogInfo.errors?.push((err as Error).toString());
        }
        for (const key of issuerLogInfo.keys) {
            if (key.crlVersion) {
                try {
                    const crlURL = `${issuer.iss}/.well-known/crl/${key.kid}.json`;
                    if (verbose) console.log("fetching CRL at " + crlURL);
                    const response = await got(crlURL, { timeout:5000 });
                    if (!response) {
                        throw "Can't reach CRL at " + crlURL;
                    }
                    const crl = JSON.parse(response.body) as CRL;
                    if (!crl) {
                        throw "Can't parse CRL at " + crlURL;
                    }
                    issuerLogInfo.crls?.push(crl);
                } catch (err) {
                    issuerLogInfo.errors?.push((err as Error).toString());
                }
            }
        }
        issuerLogInfoArray.push(issuerLogInfo);
        process.stdout.write("."); // print progress marker (without newline, unlike console.log)
    }

    const directoryLog: DirectoryLog = {
        directory: directoryUrl,
        time: date.format(currentTime, 'YYYY-MM-DDTHH:mm:ss', outputUTC).concat('Z'),
        issuerInfo: issuerLogInfoArray
    }

    return directoryLog;
}

// get duplicates in a string array
function getDuplicates(array: string[]) : string[] {
    const set = new Set(array);
    const duplicates = array.filter(item => {
        if (set.has(item)) {
            set.delete(item);
        } else {
            return item;
        }
    });
    return Array.from(new Set(duplicates));
}

// audit the directory, optionaly comparing it to a previously obtained directory
function audit(isTest: boolean, currentLog: DirectoryLog, previousLog: DirectoryLog | undefined) : AuditLog {
    // get the issuer URL. If using our test files, replace "audit-*" with "audit" (we iterate on the audit folder name
    // to simulate changes over time)
    const getIssuerUrl = (iss: string) => isTest ? iss.replace(/audit-\d/,'audit') : iss;
    // get the issuers from a directory log
    const getIssuers = (dir: DirectoryLog) => dir.issuerInfo.map(info => getIssuerUrl(info.issuer.iss));
    const currentIss = getIssuers(currentLog);
    const auditLog: AuditLog = {
        directory: currentLog.directory,
        auditTime: currentLog.time,
        issuerCount: currentLog.issuerInfo.length,
        issuersWithErrors: currentLog.issuerInfo.filter(info => info.errors != undefined && info.errors.length > 0),
        issuerWithCRLCount: currentLog.issuerInfo.filter(info => info.crls != undefined && info.crls.length > 0).length,
        duplicatedKids: getDuplicates(currentLog.issuerInfo.flatMap(info => info.keys.map(key => key.kid))),
        duplicatedIss: getDuplicates(currentIss),
        duplicatedNames: getDuplicates(currentLog.issuerInfo.map(info => info.issuer.name))
    }
    if (previousLog) {
        auditLog.previousAuditTime = previousLog?.time;
        const initialCount = 0;
        const previousIss = getIssuers(previousLog);
        auditLog.newIssuerCount = currentIss.reduce((acc, current) => acc + (previousIss.includes(current) ? 0 : 1), initialCount);
        auditLog.deletedIssuerCount = previousIss.reduce((acc, current) => acc + (currentIss.includes(current) ? 0 : 1), initialCount);
        const getIssuerKids = (dir: DirectoryLog) => dir.issuerInfo.map(info => { return { iss: getIssuerUrl(info.issuer.iss), kids: info.keys.map(key => key.kid)}});
        const currentIssKids: IssuerKids[] = getIssuerKids(currentLog);
        const previousIssKids: IssuerKids[] = getIssuerKids(previousLog);
        auditLog.removedKids = [];
        previousIssKids.forEach(pik => {
            currentIssKids.forEach(cik => {
                if (pik.iss === cik.iss) {
                    const removedKids: string[] = [];
                    pik.kids.forEach(kid => {
                        if (!cik.kids.includes(kid)) {
                            removedKids.push(kid);
                        }
                    })
                    if (removedKids.length > 0) {
                        auditLog.removedKids?.push({iss: pik.iss, kids: removedKids});
                    }
                }
            })
        });
    }
    
    return auditLog;
}


// main
void (async () => {
    console.log(`Auditing ${options.directory}`);
    try {
        var directoryLog: DirectoryLog | undefined = undefined;
        if (options.inlog) {
            // read a previously retrieved directory log
            let errMsg = `Can't read ${options.inlog}`;
            try {
                directoryLog = JSON.parse(fs.readFileSync(options.inlog).toString('utf-8')) as DirectoryLog;
            } catch (e) {
                errMsg += (". " + (e as Error).message);
            }
            if (!directoryLog) {
                console.log(errMsg);
            }
        }
        else {
            // fetch a fresh copy of the directory
            directoryLog = await fetchDirectory(options.directory, options.verbose);
            fs.writeFileSync(options.outlog, JSON.stringify(directoryLog, null, 4));
            console.log(`Directory log written to ${options.outlog}`);
        }

        if (!directoryLog) {
            throw "No directory available; aborting";
        }

        let previousDirectoryLog: DirectoryLog | undefined = undefined;
        if (options.previous) {
            let errMsg = `Can't read ${options.previous}`;
            try {
                previousDirectoryLog = JSON.parse(fs.readFileSync(options.previous).toString('utf-8')) as DirectoryLog;
            } catch (e) {
                errMsg += (". " + (e as Error).message);
            }
            if (!previousDirectoryLog) {
                console.log(errMsg);
            }
        }

        const auditLog = audit(options.test, directoryLog, previousDirectoryLog);
        fs.writeFileSync(options.auditlog, JSON.stringify(auditLog, null, 4));
        console.log(`Audit log written to ${options.auditlog}`);
    } catch (err) {
        console.log(err);
    }
})();