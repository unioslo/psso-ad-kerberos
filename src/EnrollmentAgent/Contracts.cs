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
/// Request body from Keycloak's AgentServiceClient. The CSR is base64 PKCS#10 DER; the private key
/// stays in Keycloak and is never sent.
/// </summary>
public sealed record IssueRequest(string Username, string Realm, string Csr);

/// <summary>Success response: the issued certificate, base64 DER.</summary>
public sealed record IssueResponse(string Certificate);

/// <summary>Error response: a human-readable reason (never secret material).</summary>
public sealed record ErrorResponse(string Error);

/// <summary>Thrown by an <see cref="IEnrollmentService"/> when enrollment is refused or fails.</summary>
public sealed class EnrollmentException : Exception
{
    public EnrollmentException(string message) : base(message) { }
    public EnrollmentException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Turns a user's CSR into an AD CS-issued certificate on that user's behalf. Isolated behind an
/// interface so the COM-based implementation can be swapped for a stub in tests, and so the HTTP
/// layer carries no Windows dependency.
/// </summary>
public interface IEnrollmentService
{
    /// <param name="username">sAMAccountName to enroll for.</param>
    /// <param name="realm">Kerberos realm, used to derive the NetBIOS domain if not configured.</param>
    /// <param name="csrDer">The requester's PKCS#10, DER-encoded.</param>
    /// <returns>The issued certificate, DER-encoded.</returns>
    byte[] Issue(string username, string realm, byte[] csrDer);
}
