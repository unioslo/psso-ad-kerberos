/* Copyright 2026 University of Oslo, Norway
 # This file is part of the PSSO AD Kerberos enrollment agent codebase.
 #
 # This service is free software; you can redistribute
 # it and/or modify it under the terms of the GNU General Public License
 # as published by the Free Software Foundation;
 # either version 2 of the License, or (at your option) any later version.
 #
 # This service is distributed in the hope that it will be useful, but
 # WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this service; if not, write to the Free Software Foundation,
 # Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
*/
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;

namespace EnrollmentAgent;

/// <summary>
/// Enroll-on-behalf-of against AD CS using the CertEnroll + CertCli COM APIs.
///
/// This is the TrueSSO pattern: the service holds an enrollment-agent certificate, wraps the user's
/// PKCS#10 in a CMC request, signs that CMC with the agent certificate, names the target user as
/// the requester, and submits it to the CA. AD CS — provided the service is a registered
/// (restricted) enrollment agent for the template — issues a logon certificate carrying the user's
/// identity, including the SID extension required since KB5014754.
///
/// COM is accessed by late binding (dynamic + ProgID) so no interop assembly is needed.
///
/// NOTE: the exact CertEnroll CMC incantation is fiddly and version-sensitive. This is a faithful
/// first implementation; expect to iterate against a live AD CS (template name vs. OID, requester
/// name format, whether the template is set on the inner request or the CMC). The non-COM parts of
/// the service are deliberately kept free of this so they can be exercised independently.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CertEnrollEnrollmentService : IEnrollmentService
{
    // CertEnroll encoding constants (CERTENROLL EncodingType).
    private const int XCN_CRYPT_STRING_BASE64 = 0x1;

    // CertCli submit/retrieve flags (CERTCLI).
    private const int CR_IN_BASE64 = 0x1;
    // 0x400 = CR_IN_CMC. Note 0x100 is CR_IN_PKCS10: telling the CA "PKCS#10" while sending a
    // CMC fails with CRYPT_E_ASN1_BADTAG / "Error Parsing Request". Verified against AD CS.
    private const int CR_IN_CMC = 0x400;
    private const int CR_OUT_BASE64 = 0x1;
    private const int CR_DISP_ISSUED = 3;            // Submit() disposition: certificate issued
    private const int CR_DISP_UNDER_SUBMISSION = 5;

    private readonly AgentOptions _options;
    private readonly ILogger<CertEnrollEnrollmentService> _log;

    public CertEnrollEnrollmentService(IOptions<AgentOptions> options,
        ILogger<CertEnrollEnrollmentService> log)
    {
        _options = options.Value;
        _log = log;
    }

    public byte[] Issue(string username, string realm, byte[] csrDer)
    {
        string requesterName = $"{NetbiosDomain(realm)}\\{username}";
        string csrBase64 = Convert.ToBase64String(csrDer);

        dynamic? pkcs10 = null, cmc = null, signer = null, agentCert = null, request = null;
        try
        {
            using X509Certificate2 agent = LoadAgentCertificate();

            // 1. Decode the requester's PKCS#10.
            pkcs10 = CreateCom("X509Enrollment.CX509CertificateRequestPkcs10");
            pkcs10.InitializeDecode(csrBase64, XCN_CRYPT_STRING_BASE64);

            // 2. Wrap it in a CMC request.
            cmc = CreateCom("X509Enrollment.CX509CertificateRequestCmc");
            cmc.InitializeFromInnerRequest(pkcs10);

            // 3. Name the user we enroll on behalf of. The template is NOT set here:
            //    CX509CertificateRequestCmc exposes no TemplateObjectId member ("Could not find
            //    member"); it is passed to the CA as a Submit attribute below instead.
            cmc.RequesterName = requesterName;

            // 4. Sign the CMC with the enrollment-agent certificate.
            signer = CreateCom("X509Enrollment.CSignerCertificate");
            // Initialize(MachineContext, VerifyType, EncodingType, strCertificate)
            signer.Initialize(IsMachineStore(), 0 /* VerifyNone */, XCN_CRYPT_STRING_BASE64,
                Convert.ToBase64String(agent.RawData));
            cmc.SignerCertificate = signer;

            cmc.Encode();
            // Parameterised COM property: via IDispatch late binding this is invoked as a call, not as
            // get_RawData (which dynamic cannot resolve on System.__ComObject).
            string cmcBase64 = cmc.RawData(XCN_CRYPT_STRING_BASE64);

            // 5. Submit to the CA.
            request = CreateCom("CertificateAuthority.Request");
            string attributes = $"CertificateTemplate:{_options.Template}";
            int disposition = request.Submit(CR_IN_BASE64 | CR_IN_CMC, cmcBase64, attributes, _options.CaConfig);

            if (disposition == CR_DISP_UNDER_SUBMISSION)
            {
                throw new EnrollmentException(
                    "CA left the request pending manager approval; the template must issue without approval.");
            }
            if (disposition != CR_DISP_ISSUED)
            {
                string status = SafeDispositionMessage(request);
                throw new EnrollmentException(
                    $"CA did not issue the certificate (disposition {disposition}): {status}");
            }

            string issuedBase64 = request.GetCertificate(CR_OUT_BASE64);
            _log.LogInformation("Issued certificate for {Requester} from template {Template}.",
                requesterName, _options.Template);
            return Convert.FromBase64String(StripPem(issuedBase64));
        }
        catch (EnrollmentException)
        {
            throw;
        }
        catch (Exception e)
        {
            throw new EnrollmentException($"Enrollment failed for {requesterName}: {e.Message}", e);
        }
        finally
        {
            Release(request);
            Release(signer);
            Release(cmc);
            Release(pkcs10);
            Release(agentCert);
        }
    }

    private X509Certificate2 LoadAgentCertificate()
    {
        var location = IsMachineStore() ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
        using var store = new X509Store(StoreName.My, location);
        store.Open(OpenFlags.ReadOnly);
        string wanted = Normalize(_options.AgentCertThumbprint);
        foreach (var cert in store.Certificates)
        {
            if (Normalize(cert.Thumbprint) == wanted)
            {
                if (!cert.HasPrivateKey)
                {
                    throw new EnrollmentException(
                        "The enrollment-agent certificate has no accessible private key for the service account.");
                }
                return cert;
            }
        }
        throw new EnrollmentException(
            $"Enrollment-agent certificate {_options.AgentCertThumbprint} not found in " +
            $"{location}\\My.");
    }

    private bool IsMachineStore() =>
        string.Equals(_options.AgentCertStoreLocation, "LocalMachine", StringComparison.OrdinalIgnoreCase);


    private string NetbiosDomain(string realm)
    {
        if (!string.IsNullOrWhiteSpace(_options.NetbiosDomain))
        {
            return _options.NetbiosDomain;
        }
        int dot = realm.IndexOf('.');
        return (dot > 0 ? realm[..dot] : realm).ToUpperInvariant();
    }

    private static string SafeDispositionMessage(dynamic request)
    {
        try { return request.GetDispositionMessage(); }
        catch { return "(no disposition message)"; }
    }

    private static dynamic CreateCom(string progId)
    {
        Type? type = Type.GetTypeFromProgID(progId);
        if (type is null)
        {
            throw new EnrollmentException($"COM class {progId} is unavailable; is this host Windows with AD CS client tools?");
        }
        return Activator.CreateInstance(type)!;
    }

    private static void Release(object? comObject)
    {
        if (comObject is not null && Marshal.IsComObject(comObject))
        {
            Marshal.FinalReleaseComObject(comObject);
        }
    }

    private static string Normalize(string? thumbprint) =>
        (thumbprint ?? "").Replace(":", "").Replace(" ", "").Trim().ToUpperInvariant();

    private static string StripPem(string value) => value
        .Replace("-----BEGIN CERTIFICATE-----", "")
        .Replace("-----END CERTIFICATE-----", "")
        .Replace("\r", "").Replace("\n", "").Trim();
}
