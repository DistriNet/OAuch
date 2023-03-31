using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Enumerations {
    public enum ResponseModes {
        [Display(Name = "Default grant response mode")]
        Default = 0,
        [Display(Name = "Form Post")]
        FormPost = 1,
        [Display(Name = "Query")]
        Query = 2,
        [Display(Name = "Fragment")]
        Fragment = 4,
        [Display(Name = "Response JWT (default)")]
        Jwt = 9,
        [Display(Name = "Resonse JWT (form post)")]
        FormPostJwt = 10,
        [Display(Name = "Response JWT (fragment)")]
        FragmentJwt = 11,
        [Display(Name = "Response JWT (query)")]
        QueryJwt = 12,
        [Display(Name = "Auto-detect")]
        AutoDetect = 100
    }
}
