using OAuch.OAuthThreatModel.Enrichers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.OAuthThreatModel.Consequences {
    public static class ConsequenceTypes {
        static ConsequenceTypes() {
            AccessTokenLeaked = ConsequenceType.CreateConsequence("Access Token leaked", "The access token is leaked; this is not yet a vulnerability if the access token is sender constrained.");
            AuthorizationCodeLeaked = ConsequenceType.CreateConsequence("Authorization Code leaked", "The authorization code is leaked");
            ClientAuthenticationSidestepped = ConsequenceType.CreateConsequence("Client Authentication sidestepped", "The client authentication is sidestepped because the client is a public client or the client secret is leaked");
            DataInterception = ConsequenceType.CreateConsequence("Data can be intercepted", "Data can be intercepted on the network because a deprecated version of TLS or no encryption at all is used");
            PasswordLeaked = ConsequenceType.CreateVulnerability("User Password leaked", "The user password is leaked");
            Phishing = ConsequenceType.CreateVulnerability("Phishing", "A phishing attack may be facilitated");
            PrivilegeEscalation = ConsequenceType.CreateVulnerability("Privilege Escalation", "The attacker gains access to more privileges than intended");
            RefreshTokenLeaked = ConsequenceType.CreateConsequence("Refresh Token leaked", "The refresh token is leaked");
            SessionAuthenticationSidestepped = ConsequenceType.CreateConsequence("Session Authentication sidestepped", "The session authentication is sidestepped because the doesn't use PKCE or an alternative countermeasure");
            UsableAccessTokenLeaked = ConsequenceType.CreateVulnerability("Usable Access Token leaked", "An access token that is usable by the attacker (e.g., a bearer token or an access token for which the attacker is authorized to use it) is leaked");
            DenialOfService = ConsequenceType.CreateConsequence("Denial of Service", "The authorization server cannot process more requests");
            StateLeaked = ConsequenceType.CreateConsequence("State leaked", "The value of the 'state' parameter is leaked");

            IsPublicClient = ConsequenceType.CreateConsequence("The client is a public client (i.e., it does not use client authentication).", "");
            IsConfidentialClient = ConsequenceType.CreateConsequence("The client is a confidential client (i.e., it uses client authentication).", "");
            UsesAuthorizationServer = ConsequenceType.CreateConsequence("The authorization grant involves sending the user to the authorization server.", "");
            NoSessionAuthentication = ConsequenceType.CreateConsequence("The authorization grant does not authenticate the session on the server side.", "");

            HasAuthorizationCode = ConsequenceType.CreateConsequence("Has authorizaton code", "The authorization code flow is used");
            HasTokenInFrontChannel = ConsequenceType.CreateConsequence("Has token in front-channel", "The access token is sent directly to the user's browser");
            ClientHoldsUserPassword = ConsequenceType.CreateConsequence("Client holds user password", "The user's password is used directly in the client");
            MachineToMachine = ConsequenceType.CreateConsequence("Machine-to-machine", "The flow doesn't involve a user");
            HasRefreshToken = ConsequenceType.CreateConsequence("Refresh Token", "Has refresh token");
            
            ClientUsesMultipleAuthServers = ConsequenceType.CreateConsequence("Client uses multiple authorization servers", "The client supports authorization/login via multiple authorization servers");
            ClientUsesMultipleResourceServers = ConsequenceType.CreateConsequence("Client uses multiple resource servers", "The client is not bound to one specific resource server (and its URL) at development time, but client instances are provided with the resource server URL at runtime");
            Uses307Redirect = ConsequenceType.CreateConsequence("Authorization server uses a HTTP 307 redirect", "When the status code 307 is used for redirection, the user agent will send the user's credentials via HTTP POST to the client.");
            UsesReverseProxy = ConsequenceType.CreateConsequence("HTTP Application uses a Reverse Proxy", "If the reverse proxy would pass through any header sent from the outside, an attacker could try to directly send the faked header values through the proxy to the application server in order to circumvent security controls that way.");
            ClientCanChooseId = ConsequenceType.CreateConsequence("Clients can influence their Client Id", "If a client is able to choose its own client_id during registration with the authorization server, a malicious client may set it to a value identifying an end-user (e.g., a sub value if OpenID Connect is used).");
            UsesPostMessage = ConsequenceType.CreateConsequence("The authorization response is sent with in -browser communication techniques like postMessage", "If the authorization response is sent with in-browser communication techniques like postMessage instead of HTTP redirects, messages may inadvertently be sent to malicious origins or injected from malicious origins.");
        }

        public static IEnumerable<ConsequenceType> All {
            get {
                var type = typeof(ConsequenceTypes);
                var props = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
                var ct = typeof(ConsequenceType);
                return props.Where(p => p.PropertyType == ct).Select(p => (ConsequenceType)p.GetValue(null)!);
            }
        }

        // Threat consequences
        public static ConsequenceType AccessTokenLeaked { get; }
        public static ConsequenceType AuthorizationCodeLeaked { get; }
        public static ConsequenceType ClientAuthenticationSidestepped { get; }
        public static ConsequenceType NoSessionAuthentication { get; }
        public static ConsequenceType DataInterception { get; }
        public static ConsequenceType PasswordLeaked { get; }
        public static ConsequenceType Phishing { get; }
        public static ConsequenceType PrivilegeEscalation { get; }
        public static ConsequenceType RefreshTokenLeaked { get; }
        public static ConsequenceType SessionAuthenticationSidestepped { get; }
        public static ConsequenceType UsableAccessTokenLeaked { get; }
        public static ConsequenceType DenialOfService { get; }
        public static ConsequenceType StateLeaked { get; }

        // Flow consequences
        public static ConsequenceType IsPublicClient { get; }
        public static ConsequenceType IsConfidentialClient { get; }
        public static ConsequenceType UsesAuthorizationServer { get; }
        public static ConsequenceType HasAuthorizationCode { get; }
        public static ConsequenceType HasTokenInFrontChannel { get; }
        public static ConsequenceType ClientHoldsUserPassword { get; }
        public static ConsequenceType MachineToMachine { get; }
        public static ConsequenceType HasRefreshToken { get; }

        // Special requirements (do we need these?)
        public static ConsequenceType ClientUsesMultipleAuthServers { get; }
        public static ConsequenceType ClientUsesMultipleResourceServers { get; }
        public static ConsequenceType Uses307Redirect { get; }
        public static ConsequenceType UsesReverseProxy { get; }
        public static ConsequenceType ClientCanChooseId { get; }
        public static ConsequenceType UsesPostMessage { get; }
    }
}