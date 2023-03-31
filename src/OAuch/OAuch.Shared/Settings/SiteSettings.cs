using Newtonsoft.Json;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Settings {
    /// <summary>
    /// Holds all the settings of a site
    /// </summary>

    public record ClientSettings {
        public string? ClientId { get; set; }
        public string? ClientSecret { get; set; }
        public string? Scope { get; set; }
    }
    public record GrantOverride { 
        public string? FlowType { get; set; }
        public ClientSettings? OverrideSettings { get; set; }
    }
    public record SiteSettings {
        public SiteSettings() {
            this.SelectedStandards = new List<string>();
            this.DefaultClient = new ClientSettings();
            this.AlternativeClient = new ClientSettings();
        }
        /// <summary>
        /// Holds the identifiers of the standards (RFCs/drafts) that the user selected to test
        /// </summary>
        public IList<string>? SelectedStandards { get; set; }

        // URIs
        public string? MetadataUri { get; set; }
        public string? AuthorizationUri { get; set; }
        public string? DeviceAuthorizationUri { get; set; }
        public string? TokenUri { get; set; }
        public string? CallbackUri { get; set; }
        public string? RevocationUri { get; set; }
        public string? JwksUri { get; set; }

        // Client settings
        public ClientSettings DefaultClient { get; set; }
        public ClientSettings AlternativeClient { get; set; }

        public ClientSettings GetClient(string flowType) {
            var defs = this.DefaultClient;
            // fix settings by applying override settings
            ClientSettings? ovr = this.Overrides?.Where(c => c.FlowType == flowType).Select(c => c.OverrideSettings).FirstOrDefault();
            if (ovr != null) {
                defs = new ClientSettings {
                    ClientId = Fix(defs?.ClientId, ovr?.ClientId),
                    ClientSecret = Fix(defs?.ClientSecret, ovr?.ClientSecret),
                    Scope = Fix(defs?.Scope, ovr?.Scope),
                };
            }
            return defs;

            string? Fix(string? def, string? ovr) {
                if (string.IsNullOrWhiteSpace(ovr))
                    return def;
                return ovr;
            }
        }

        public List<GrantOverride> Overrides { get; set; }

        public string? Username { get; set; }
        public string? Password { get; set; }

        // TestUri settings
        public string? TestUri { get; set; }
        public HttpMethodsEnum TestMethod { get; set; }
        public string? TestHeaders { get; set; }
        public string? TestPostData { get; set; }

        // OpenID settings
        public string? OpenIdIssuer { get; set; }
        //public OpenIdHybridResponseTypes HybridResponseType { get; set; }
        //public OpenIdImplicitResponseTypes ImplicitResponseType { get; set; }
        public PKCESupportTypes PKCEDefault { get; set; }

        // Various settings
        public int TokenDelay { get; set; }
        //public ResponseModes? AuthorizationCodeResponseMode { get; set; }

        public ResponseModes ResponseMode { get; set; }
        public bool UseRequestParameter { get; set; }
        public string? RequestSigningKey { get; set; }
        public ClientAuthenticationMechanisms ClientAuthenticationMechanism { get; set; }
        public string? RequestAudience { get; set; }
        public IList<string>? ExcludedFlows { get; set; }

        public Guid? CertificateId { get; set; }
        [JsonIgnore]
        public X509CertificateCollection Certificates {
            get {
                if (_certificates == null) {
                    if (this.CertificateId != null) {
                        var resolver = ServiceLocator.Resolve<ICertificateResolver>();
                        _certificates = resolver?.FindCertificate(this.CertificateId.Value);
                        if (_certificates == null)
                            this.CertificateId = null; // certificate doesn't exist anymore (deleted?)
                    }
                    if (_certificates == null) {
                        _certificates = new X509CertificateCollection();
                    }
                }
                return _certificates;
            }
            set {
                _certificates = value;
            }
        }
        private X509CertificateCollection? _certificates;

        [JsonIgnore]
        public bool IsConfidentialClient {
            get {
                if (CertificateId != null)
                    return true; // uses mTLS
                if (ClientAuthenticationMechanism == ClientAuthenticationMechanisms.PrivateKeyJwt && !string.IsNullOrEmpty(RequestSigningKey))
                    return true; // uses PrivateKeyJwt
                if (ClientAuthenticationMechanism != ClientAuthenticationMechanisms.PrivateKeyJwt && !string.IsNullOrEmpty(DefaultClient.ClientSecret))
                    return true; // ClientSecret using Post, Basic or SecretKeyJwt
                return false;
            }
        }
    }
}
