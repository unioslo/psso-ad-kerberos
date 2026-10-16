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
using System.Security.Cryptography.X509Certificates;
using EnrollmentAgent;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<AgentOptions>(builder.Configuration.GetSection(AgentOptions.SectionName));

// The enrollment service is Windows/COM-only. Registered unconditionally because the whole service
// only runs on Windows; a non-Windows build would fail fast at first call with a clear message.
builder.Services.AddSingleton<IEnrollmentService, CertEnrollEnrollmentService>();

// Mutual TLS, configured entirely in code rather than via a Kestrel config section.
//
// Two reasons it must be explicit: with a config-declared endpoint it is ambiguous whether
// ConfigureHttpsDefaults applies, and revocation checking has to be off. This is a private PKI
// with no OCSP responder, and Schannel otherwise aborts the handshake before Kestrel sees it,
// logging System event 36928 "Could not retrieve an OCSP response" with an empty OCSP URL.
var agentConfig = builder.Configuration.GetSection(AgentOptions.SectionName).Get<AgentOptions>()
                  ?? new AgentOptions();

builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenAnyIP(agentConfig.ListenPort, listen =>
    {
        listen.UseHttps(https =>
        {
            https.ServerCertificate = LoadServerCertificate(agentConfig.ServerCertSubject);
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.CheckCertificateRevocation = false;
            // Accept at the TLS layer; the certificate auth handler below does the real check and
            // pins Keycloak by thumbprint. Validating here would mean a revocation lookup that
            // cannot succeed without a responder.
            https.ClientCertificateValidation = (_, _, _) => true;
        });
    });
});

static X509Certificate2 LoadServerCertificate(string subject)
{
    using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadOnly);
    foreach (var cert in store.Certificates)
    {
        if (cert.Subject.Contains(subject, StringComparison.OrdinalIgnoreCase) && cert.HasPrivateKey)
        {
            return cert;
        }
    }
    throw new InvalidOperationException(
        $"No TLS server certificate with subject containing '{subject}' and an accessible private "
        + "key was found in LocalMachine\\My.");
}

builder.Services
    .AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        // Trust is anchored by the host certificate store; pin the specific client below.
        options.AllowedCertificateTypes = CertificateTypes.Chained;
        options.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                var opts = context.HttpContext.RequestServices
                    .GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentOptions>>().Value;
                if (!ClientAllowed(context.ClientCertificate, opts))
                {
                    context.Fail("Client certificate is not an allowed enrollment client.");
                }
                else
                {
                    context.Success();
                }
                return Task.CompletedTask;
            }
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok("ok"));

app.MapPost("/issue", (IssueRequest request, IEnrollmentService enrollment, ILogger<Program> log) =>
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Realm)
        || string.IsNullOrWhiteSpace(request.Csr))
    {
        return Results.BadRequest(new ErrorResponse("username, realm and csr are all required."));
    }

    var opts = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentOptions>>().Value;
    if (opts.AllowedPrincipals.Count > 0
        && !opts.AllowedPrincipals.Contains(request.Username, StringComparer.OrdinalIgnoreCase))
    {
        // Defence in depth behind the CA's restricted-enrollment-agent scoping.
        log.LogWarning("Refused enrollment for {User}: not in AllowedPrincipals.", request.Username);
        return Results.Json(new ErrorResponse("principal not permitted"), statusCode: 403);
    }

    byte[] csrDer;
    try
    {
        csrDer = Convert.FromBase64String(request.Csr);
    }
    catch (FormatException)
    {
        return Results.BadRequest(new ErrorResponse("csr is not valid base64."));
    }

    try
    {
        byte[] cert = enrollment.Issue(request.Username, request.Realm, csrDer);
        return Results.Ok(new IssueResponse(Convert.ToBase64String(cert)));
    }
    catch (EnrollmentException e)
    {
        log.LogError(e, "Enrollment failed for {User}@{Realm}.", request.Username, request.Realm);
        return Results.Json(new ErrorResponse(e.Message), statusCode: 502);
    }
}).RequireAuthorization();

app.Run();

static bool ClientAllowed(X509Certificate2? clientCert, AgentOptions opts)
{
    if (clientCert is null)
    {
        return false;
    }
    if (opts.AllowedClientThumbprints.Count == 0)
    {
        return true; // chain validation already happened; no specific pin configured
    }
    string actual = clientCert.Thumbprint.Replace(":", "").Replace(" ", "").Trim();
    return opts.AllowedClientThumbprints
        .Select(t => t.Replace(":", "").Replace(" ", "").Trim())
        .Any(t => string.Equals(t, actual, StringComparison.OrdinalIgnoreCase));
}

// Exposed so the contract and options are reachable from a test project if one is added.
public partial class Program { }
