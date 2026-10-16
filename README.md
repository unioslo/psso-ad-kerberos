# PSSO AD Kerberos — enrollment agent service

A small Windows service that lets the
[keycloak-psso-extension](https://github.com/unioslo/keycloak-psso-extension) obtain Kerberos
tickets for **Active Directory** users during passwordless Platform SSO logins.

Keycloak cannot do PKINIT against AD by itself: AD scopes certificate trust only at the CA (the
NTAuth store is forest-wide and cannot be narrowed per user), so a Keycloak-held CA would be able
to impersonate anyone. This service is the TrueSSO answer — it holds an **enrollment-agent**
certificate and asks your existing **AD CS** to issue a short-lived logon certificate *on the
user's behalf*, scoped by AD CS's native *Restricted Enrollment Agent* feature. The user's private
key is generated in Keycloak and never reaches this service.

```
Mac (Secure Enclave login, no password)
  -> Keycloak PSSO extension: generate keypair + CSR
  -> [mutual TLS] POST /issue {username, realm, csr}   <-- this service
       -> CertEnroll: wrap CSR in CMC, sign with agent cert, set requester = user
       -> AD CS (ICertRequest.Submit): issue logon cert for the user
  <- {certificate}
  -> Keycloak: PKINIT AS-REQ with (cert + local key) -> TGT -> login response -> Mac
```

> **Status: working, verified end to end against a live AD CS and a real Mac (2026-10-16).**
> A Mac signing in via Platform SSO receives a Kerberos TGT issued through this service and
> imports it into its credential cache. See [Verified behaviour](#verified-behaviour) for what
> exactly was tested, and [Known limitation](#known-limitation-guest-accounts) for the one case
> that does not work (a macOS issue, not this service).

## Contract (must match the extension's `AgentServiceClient`)

```
POST {AgentServiceUrl}            (mutual TLS)
Content-Type: application/json
  { "username": "alice", "realm": "AD.EXAMPLE.COM", "csr": "<base64 PKCS#10 DER>" }

200 OK   { "certificate": "<base64 DER>" }
4xx/5xx  { "error": "<human-readable reason>" }
```

The `csr` carries the public key and a UPN SAN; the matching **private key stays in Keycloak**.

## Requirements

- Windows Server, **domain-joined**, with the AD CS client tools present (CertEnroll/CertCli COM —
  standard on Windows Server). Not a domain controller; no other role needed.
- .NET 8 SDK (`net8.0-windows`).
- Network path to the issuing CA's DCOM endpoints (the native submit uses RPC/DCOM). If the agent
  sits in a different firewall zone from the CA, pin the CA's DCOM port or switch to CES — the
  enrollment step is isolated behind `IEnrollmentService` for exactly that.

## AD CS prerequisites (do these first)

On the CA (`certtmpl.msc` / `certsrv.msc`), as a CA admin:

1. **Enrollment Agent template** — duplicate *Enrollment Agent*, grant the service account
   **Read + Enroll**, publish it. Enroll the service account for this cert; note its SHA-1
   thumbprint (→ `Agent:AgentCertThumbprint`).
2. **Logon template** — duplicate *Smartcard Logon* ("PSSOKerberosLogon"):
   - *Subject Name* → **Supply in the request**.
   - *Issuance Requirements* → **1 authorized signature**, policy type *Application policy*,
     policy **Certificate Request Agent**.
   - *Security* → grant the PSSO user group **Read + Enroll**.
   - Short validity; confirm the Smart Card Logon EKU is present.
   - Publish it (→ `Agent:Template`).
3. **Restricted Enrollment Agent** — `certsrv.msc` → CA → Properties → *Enrollment Agents* tab →
   restrict the service account to the logon template and the PSSO group. This is the control that
   stops a compromised agent minting a certificate for a Domain Admin — do not skip it.

AD CS adds the KB5014754 SID extension automatically when issuing from a template, so strong
certificate mapping just works — one of the main reasons to use AD CS rather than a private CA.

## Configuration

Edit `appsettings.json` (or `appsettings.Local.json`, gitignored). Key fields in `AgentOptions.cs`:

| Key | Value |
|---|---|
| `CaConfig` | `CAHOST\CA Common Name` (`certutil -config - -ping` to find it) |
| `Template` | logon template name, e.g. `PSSOKerberosLogon` |
| `AgentCertThumbprint` | SHA-1 thumbprint of the enrollment-agent cert |
| `AgentCertStoreLocation` | `CurrentUser` (service account) or `LocalMachine` |
| `NetbiosDomain` | NetBIOS domain for the requester name; empty = first realm label |
| `AllowedClientThumbprints` | pin Keycloak's mTLS client cert(s); empty = any chain-valid client |
| `AllowedPrincipals` | optional sAMAccountName allow-list (defence in depth) |

TLS: the `Kestrel` section binds the service's own server certificate (used for mTLS); run it
behind that on `https://…:8443`. Point the extension's `kerberosAgentServiceUrl` at
`https://<this-host>:8443/issue`, give it a client cert this service trusts, and put this service's
server CA in the extension's `kerberosAgentServerCa`.

## Build & run

```powershell
dotnet build src/EnrollmentAgent/EnrollmentAgent.csproj
dotnet run   --project src/EnrollmentAgent/EnrollmentAgent.csproj
# mutual TLS is required on every request, so a client certificate is mandatory:
# curl --cert keycloak-client.crt --key keycloak-client.key --cacert your-ca.pem \
#      https://<host>:8443/health
#
# NOTE: bind/connect by IP or FQDN consistently - the service's TLS certificate must carry a
# matching SAN. "localhost" resolves to ::1 first on Windows, which bites if you bind IPv4 only.
```

For production, publish as a Windows Service (`sc.exe create` / a service host) running as the
account that holds the enrollment-agent certificate.

## Security notes

- The agent certificate is the sensitive asset — keep it in the service account's store (TPM/HSM
  if available), never export it to the extension or anywhere else.
- Scope both at the CA (Restricted Enrollment Agent) **and** here (`AllowedPrincipals`,
  `AllowedClientThumbprints`).
- Residual risk: a compromise of this service can obtain a logon certificate for any member of the
  permitted group. The restricted agent bounds the blast radius; it does not eliminate it.
- Never add the extension's local CA (the FreeIPA path's CA) to AD's NTAuth — this service exists
  precisely so you don't.

## Verified behaviour

Tested against Windows Server 2022 AD CS (`Babb Test CA`), a Keycloak 26.x realm, and macOS 27.2:

- Keycloak POSTs a CSR over mutual TLS; this service co-signs it as an enrollment agent and AD CS
  issues a logon certificate **on the user's behalf** — the CA database records
  `Requester Name: DOMAIN\user`, `Caller Name: DOMAIN\agent-account`.
- The issued certificate carries the UPN SAN, Smart Card Logon + Client Authentication EKUs, and
  the **SID extension** (`1.3.6.1.4.1.311.25.2`) required by KB5014754 strong mapping.
- Keycloak then completes PKINIT against the DC and the Mac imports the resulting TGT.

### Known limitation: guest accounts

A macOS **guest / temporary** account signing in with a non-password method does **not** receive a
ticket *on the first login after a restart*; subsequent authentications do. macOS fails to decrypt
its own pending SSO tokens before any Kerberos processing happens
(`failed to decrypt tokens when decrypting pending sso tokens`, `ECIES: Failed to aes-gcm decrypt
data (err -69)`), so the ticket in the login response is never examined. Normal (non-guest)
accounts are unaffected. This is a macOS issue, reported to Apple; nothing in this service or the
Keycloak extension is involved.

## Implementation notes

Four things cost real debugging time and are easy to reintroduce:

1. **`CR_IN_CMC` is `0x400`.** `0x100` is `CR_IN_PKCS10`; submitting a CMC with it fails as
   `CRYPT_E_ASN1_BADTAG` / "Error Parsing Request".
2. **`CX509CertificateRequestCmc` has no `TemplateObjectId` member** ("Could not find member").
   Pass the template to the CA as the Submit attribute string `CertificateTemplate:<name>`.
3. **A parameterised COM property is a *call* under `dynamic`** — `cmc.RawData(encoding)`, not
   `cmc.get_RawData(encoding)`, which throws
   `'System.__ComObject' does not contain a definition for 'get_RawData'`.
4. **Kestrel HTTPS is configured in code, not `appsettings.json`.** From configuration it is
   ambiguous whether `ConfigureHttpsDefaults` applies, so `CheckCertificateRevocation = false`
   was ignored. With a private PKI and no OCSP responder, Schannel then aborts every handshake
   *before Kestrel logs anything* — the only trace is System event **36928 "Could not retrieve an
   OCSP response"** with an empty URL.

A further trap on the template side: do **not** set `ENROLLEE_SUPPLIES_SUBJECT` on the logon
template. AD CS will issue, but omits the SID extension, and the DC then rejects the certificate
for PKINIT. Let AD CS build the subject from the account
(`msPKI-Certificate-Name-Flag = 0x82000000`); the CSR still supplies the key. That is also the
safer arrangement, since the requester cannot dictate its own identity.

## Layout

```
src/EnrollmentAgent/
  Program.cs                      Kestrel + mutual TLS + /issue, /health
  Contracts.cs                    request/response DTOs + IEnrollmentService
  AgentOptions.cs                 configuration
  CertEnrollEnrollmentService.cs  the CertEnroll/CertCli enroll-on-behalf-of (COM)
  appsettings.json                sample config
```

## Verifying commits

Commits here are signed with the same SSH key that signs
[keycloak-psso-extension](https://github.com/unioslo/keycloak-psso-extension), so the _Verified_
badge GitHub shows on both repositories refers to one key. The public key is in
[`allowed_signers`](allowed_signers) and is also served, independently of this repository, at
https://api.github.com/users/oculos/ssh_signing_keys

```
$ git -c gpg.ssh.allowedSignersFile=allowed_signers log --show-signature -1
Good "git" signature for franciaa@uio.no with RSA key SHA256:rSbAcdqbMIYLHmnh+0xocKuxBpAmTJbwTCd8yeJKk2E
```

`-n git` is the namespace Git uses for commit signatures; a bare `ssh-keygen -Y verify` needs it
spelled out, which is why the `git log` form above is easier.

## License

Copyright 2026 University of Oslo, Norway.

Licensed under the **GNU General Public License, version 2 or later** — the same terms as the
[keycloak-psso-extension](https://github.com/unioslo/keycloak-psso-extension) this service
accompanies. See [LICENSE](LICENSE) for the full text.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
