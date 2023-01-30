# Package `openssl`
## Purpose
Handle sending commands to the `openssl` binary.

## Current Functionality
- Initialize a new CA.
    - Creates the directory structure required to service the provided configuration files for the root CA and subordinate (signing) CA.
    - Generates 4096-bit private keys for the root and subordinate CA.
    - Creates the self-signed root certificate.
    - Creates a CSR for the subordinate CA.
    - Signs and records the subordinate CA CSR.
        - TODO: need to copy the signed certificate to the issuers certificate directory...

- Listing certificates recorded in the CA database.
- Updating the CA database

## Outstanding
- Randomize the passphrase and place it in a permissions protected file to reside in the container filesystem.
- Move generate key and generate CSR to a common library for use in CLI applications.
    - CLI will facilitate generating keys and CSRs to submit to the CA for signing.
- Implement CRL generation and a method to expose obtaining the CRL.
- Implement revocation.
- Implement scheduler for DB update such that expired certificates will be updated in the DB without user interaction.
- REST API for the service
- Dockerfile / Docker compose descriptor for deployment
    - reverse proxy container (Caddy or nginx)?

## Endpoint authentication
- undecided

## REST API endpoints
`/v1/crl` - [GET] return the PEM encoded CRL
`/v1/list` - [GET] return the list of certificates stored in the CA database
`/v1/get` - [GET:jsonbody] return the PEM encoded certificate identified by a given serial number
`/v1/revoke` - [PUT:jsonbody] revoke the certificate identified by a given serial number
`/v1/sign` - [POST:jsonbody] sign the given PEM encoded CSR

## Testing
- Tests around generating ssl command arguments (unit)
- Tests around artifacts generated during initialization (intg)
- Tests around signing CSRs (intg)

## Use Cases
- Homelab services can leverage CLI tools to generate CSRs and submit them to the CA for signing and receive certificates in an automated fashion such that the CA has no knowledge of the services private keys.

## CLI commands to implement
- Generate CSR
- Submit CSR
- Request revocation
- Renew (really just revoke and submit request; option to renew with different key in case of compromised certificate)