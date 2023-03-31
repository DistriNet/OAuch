using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Enumerations {
    public enum OpenIdImplicitResponseTypes : int {
        [Display(Name = "Request an ID token and an access token ('id_token token' flow)")]
        IdTokenAndAccessToken = 0,
        [Display(Name = "Only request an ID token ('id_token' flow)")]
        IdTokenOnly = 1
    }
}
