using System.ComponentModel.DataAnnotations;

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
