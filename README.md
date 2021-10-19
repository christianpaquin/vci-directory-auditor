# vci-directory-auditor

WORK-IN-PROGRESS!

Audit tool for the [VCI directory](https://github.com/the-commons-project/vci-directory/).

## Setup

Make sure [node.js](https://nodejs.org/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) are installed on your system; the latest Long-Term Support (LTS) version is recommended for both. [OpenSSL](https://www.openssl.org/) is also needed to validate TLS connections.

1. Get the source, for example using `git`
```
git clone -b main christianpaquin/vci-directory-auditor.git
cd health-cards-dev-tools
```

2. Build the `npm` package
```
npm install
npm run build
```

3. Optionally, run the tests
Audit a test directory:
```
npm test
```

Audit an evolving test directory:
```
npm run test-audit-1
npm run test-audit-2
npm run test-audit-3
```

## Usage

```
npm run audit <options>
```
where `<options>` are:
 - `-i, --inlog <outlog>`: input log file storing directory issuer keys and TLS details; if unspecified, the directory will be downloaded from the specified location
 - `-o, --outlog <outlog>`: output log file storing directory issuer keys and TLS details
 - `-p, --previous <previous>`: directory log file from a previous audit
 - `-a, --auditlog <auditlog>`: output audit file on the directory
 - `-d, --directory <directory>`: URL of the directory to audit; uses the VCI one by default
 - `-t, --test`: test mode

## Checks

The tool does the following:
 - Download the specified issuer directory. For each issuer:
   - Download and validate its JWK set
   - Check its default TLS connection configuration (see below)
 - Store a copy of the directory with the issuer JWK sets
 - Audit the directory (optionally comparing to a previous snapshot of the directory), and report:
   - The number of issuers
   - The number of added and deleted issuers
   - Download errors
   - Duplicated KIDs, issuer names, iss URLs

### TLS validation

This tool tests conformance with [IETF BCP 195](https://www.rfc-editor.org/info/bcp195), consisting of:
  - [RFC 7525](https://www.rfc-editor.org/info/rfc7525): Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
  - [RFC 8996](https://www.rfc-editor.org/info/rfc8996): Deprecating TLS 1.0 and TLS 1.1

OpenSSL's `s_client` tool is used to connect to a specified server, testing the various aspects of the TLS connections. The following table summarizes the validated items.

|Section         |Rule|Command|Error if|Warn if|Note|
|----------------|--------------------|-------|--------|-------|----|
|3.1: TLS version|MUST support TLS 1.2    |openssl s_client -connect <server>:443 -tls1_2|fails||
|                |MUST NOT support TLS 1.0, 1.1 (and SSL)|openssl s_client -connect <server>:443 -no_tls1_2 -no_tls1_3|succeeds||From RFC 8996|
|3.2: Strict TLS |MUST support the HTTP Strict Transport Security (HSTS) header|curl -s -D- <server> \| grep -i Strict|no match||
|3.3: Compression|SHOULD disable TLS-level compression|openssl s_client ... \|  grep ""Compression: NONE"""||no match|
|3.4: TLS Session Resumption|*TODO*||||
|3.5: TLS Renegotiation|*TODO*||||
|3.6: Server Name Indication|*TODO*||||
|4.1: General Guideline|MUST NOT negotiate the cipher suites with NULL encryption. MUST NOT negotiate RC4 cipher suites. MUST NOT negotiate cipher suites offering less than 112 bits of security, including so-called "export-level" encryption (which provide 40 or 56 bits of security).|openssl s_client -connect \<server\>:443 -cipher NULL,EXPORT,LOW,3DES -tls1_2|succeeds||
||SHOULD NOT negotiate cipher suites that use algorithms offering less than 128 bits of security|*TODO*|||
||SHOULD NOT negotiate cipher suites based on RSA key transport, a.k.a. "static RSA"|*TODO*|||
||MUST support and prefer to negotiate cipher suites offering forward secrecy, such as those in DHE and ECDHE families|*TODO*|||
|4.2. Recommended Cipher Suites|The following cipher suites are RECOMMENDED:<br/> - TLS_DHE_RSA_WITH_AES_128_GCM_SHA256<br/> - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256<br/> - TLS_DHE_RSA_WITH_AES_256_GCM_SHA384<br/> - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|*TODO*|||
|4.2.1. Implementation Details|SHOULD include TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as the first proposal to any server.  Servers MUST prefer this cipher suite over weaker cipher suites whenever it is proposed, even if it is not the first proposal|*TODO*|||
||Clients and servers SHOULD include the "Supported Elliptic Curves" extension and SHOULD support the NIST P-256 (secp256r1) curve|openssl s_client -connect \<server\>:443 -curves prime256v1 \| grep "Server Temp Key: ECDH, P-256, 256 bits"||no match|openssl doesn't have curve "secp256r1". Curve "prime256v1" uses ECDHE, curve "secp256k1" uses DHE. "|
|4.3: Public Key Length|DH key lengths of at least 2048 bits are RECOMMENDED|openssl s_client ... \| grep "Server public key is "||if "xxxx bits" is < 2048|
||Curves of less than 192 bits SHOULD NOT be used|*TODO*|||
||When using RSA, servers SHOULD authenticate using certificates with at least a 2048-bit modulus for the public key|*TODO*|||
||The use of the SHA-256 hash algorithm is RECOMMENDED|*TODO*|||
|4.4: Modular Exponential vs. Elliptic Curve DH Cipher Suites|*TODO*||||
|4.5: Truncated HMAC|MUST NOT use the Truncated HMAC extension||||
|6.1: Host Name Validation|||||
