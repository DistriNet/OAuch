using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Enumerations {
    public enum PKCESupportTypes : int {
        [Display(Name = "Hashed code challenge")]
        Hash = 2,
        [Display(Name = "Plain code challenge")]
        Plain = 1,
        [Display(Name = "No code challenge")]
        None = 0
    }
}
