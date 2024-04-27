using System.ComponentModel.DataAnnotations;

namespace OAuch.Shared.Enumerations {
    public enum OpenIdHybridResponseTypes : int {
        [Display(Name = "Request an ID token from the authorization server, and an access token from the token server ('code id_token' flow)")]
        IdToken = 1,
        [Display(Name = "Request an ID token from the token server, and an access token from the authorization server ('code token' flow)")]
        Token = 2,
        [Display(Name = "Request an ID token and an access token from the authorization server ('code id_token token' flow)")]
        IdTokenToken = IdToken | Token
    }
}
