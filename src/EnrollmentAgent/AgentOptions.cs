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
namespace EnrollmentAgent;

/// <summary>
/// Configuration for the enrollment-agent service, bound from the "Agent" section of
/// appsettings.json (override per host with appsettings.Local.json or environment variables).
/// </summary>
public sealed class AgentOptions
{
    public const string SectionName = "Agent";

    /// <summary>TCP port for the mutual-TLS endpoint.</summary>
    public int ListenPort { get; set; } = 8443;

    /// <summary>
    /// Subject (substring match) of this service's own TLS server certificate, looked up in
    /// LocalMachine\My. Configured here rather than in a Kestrel config section so the HTTPS
    /// options can be set explicitly in code — see Program.cs.
    /// </summary>
    public string ServerCertSubject { get; set; } = "psso-enrollment-agent";

    /// <summary>
    /// AD CS configuration string, "CAHOST\CA Common Name" — the target of ICertRequest.Submit.
    /// Find it with <c>certutil -dump</c> or <c>certutil -config - -ping</c>.
    /// </summary>
    public string CaConfig { get; set; } = "";

    /// <summary>
    /// Certificate template to enroll from (the TrueSSO-style logon template), by its
    /// <em>template name</em> (cn), e.g. "PSSOKerberosLogon".
    /// </summary>
    public string Template { get; set; } = "";

    /// <summary>
    /// SHA-1 thumbprint of the enrollment-agent certificate, held in the service account's
    /// personal store (CurrentUser\My) or the machine store (see <see cref="AgentCertStoreLocation"/>).
    /// This certificate must have the Certificate Request Agent EKU and the CA must list the
    /// service as a restricted enrollment agent for the template above.
    /// </summary>
    public string AgentCertThumbprint { get; set; } = "";

    /// <summary>"CurrentUser" or "LocalMachine" — where the agent certificate lives.</summary>
    public string AgentCertStoreLocation { get; set; } = "CurrentUser";

    /// <summary>
    /// How to turn a realm into the NetBIOS domain for the CMC requester name
    /// ("DOMAIN\sAMAccountName"). If empty, the first DNS label of the realm is used
    /// (e.g. AD.EXAMPLE.COM -> AD). Set explicitly when they differ.
    /// </summary>
    public string NetbiosDomain { get; set; } = "";

    /// <summary>
    /// Thumbprints of client certificates Keycloak may present (mutual TLS). Empty means "trust any
    /// client cert that chains to a CA in the host trust store" — set this in production to pin
    /// Keycloak specifically. Compared case-insensitively, whitespace/colons ignored.
    /// </summary>
    public List<string> AllowedClientThumbprints { get; set; } = new();

    /// <summary>
    /// Optional allow-list of sAMAccountNames (or a group the service resolves out of band) the
    /// agent will enroll for. Empty disables the check here and relies solely on the CA's
    /// restricted-enrollment-agent scoping. Defence in depth; prefer configuring both.
    /// </summary>
    public List<string> AllowedPrincipals { get; set; } = new();
}
