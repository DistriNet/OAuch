using System.ComponentModel.DataAnnotations;

namespace OAuch.Shared.Enumerations {
    public enum ClientAuthenticationMechanisms {
        [Display(Name = "Send client secret in the HTTP basic authentication header (client_secret_basic, default)")]
        ClientSecretBasic = 0,
        [Display(Name = "Send client secret in the HTTP request body (client_secret_post)")]
        ClientSecretPost = 1,
        [Display(Name = "Use client secret to sign a JWT with a MAC (client_secret_jwt)")]
        ClientSecretJwt = 2,
        [Display(Name = "Use client key to sign a JWT with an asymmetric algorithm (private_key_jwt)")]
        PrivateKeyJwt = 3
    }
}
