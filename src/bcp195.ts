// Test conformance with IETF BCP 195 (https://www.rfc-editor.org/info/bcp195), consisting of:
//  - RFC 7525: Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
//  - RFC 8996: Deprecating TLS 1.0 and TLS 1.1

import execa from 'execa';

export interface TlsDetails {
    version: string | undefined,
    cipher: string | undefined,
    kexAlg: string | undefined,
    authAlg: string | undefined,
    pubKeySize: string | undefined,
    compression: string | undefined
}

function isOpensslAvailable(): boolean {
    try {
        const result = execa.commandSync("openssl version");
        return (result.exitCode == 0);
    } catch (err) {
        return false;
    }
}

const openssl = (args: string[]): execa.ExecaSyncReturnValue<string> => {
    let result: execa.ExecaSyncReturnValue<string>;
    try {
        result = execa.sync('openssl', args, {timeout: 2000}); // TODO: make timeout configurable
    }
    catch(err) {
        result = (err as execa.ExecaSyncReturnValue<string>);
        if (!result) {
            console.log(err);
        }
    }
    return result;
}

export function getDefaultTlsDetails(server: string): TlsDetails | undefined {
    if (!isOpensslAvailable()) {
        console.log("OpenSSL not available");
        return undefined;
    }
    const result = openssl(['s_client', '-connect', `${server}:443`]);
    if (!result || result.failed) {
        console.log(result ? result.stderr : "openssl failed");
        return undefined;
    }

    let version = result.stdout.match(new RegExp('^    Protocol  : (.*)$', 'm'))?.[1];
    let cipher = result.stdout.match(new RegExp('^    Cipher    : (.*)$', 'm'))?.[1];
    if (!version || !cipher) {
        // with some config, the previous lines are not written; parse a different line
        const match = result.stdout.match(new RegExp('^New, (.*), Cipher is (.*)$', 'm'));
        version = match?.[1];
        cipher = match?.[2];
    }
    const kexAlg = result.stdout.match(new RegExp('^Server Temp Key: (.*)$', 'm'))?.[1];
    const authAlg = result.stdout.match(new RegExp('^Peer signature type: (.*)$', 'm'))?.[1];
    const pubKeySize = result.stdout.match(new RegExp('^Server public key is ([0-9]*) bit', 'm'))?.[1];
    const compression = result.stdout.match(new RegExp('^Compression: (.*)$', 'm'))?.[1];
    const tlsDetails = {
        version: version,
        cipher: cipher,
        kexAlg: kexAlg,
        authAlg: authAlg,
        pubKeySize: pubKeySize,
        compression: compression
    }
    return tlsDetails;
}
