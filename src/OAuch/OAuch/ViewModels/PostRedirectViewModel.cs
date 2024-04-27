using System.Collections.Generic;

namespace OAuch.ViewModels {
    public class PostRedirectViewModel {
        public required string PostUrl { get; set; }
        public required Dictionary<string, string> FormValues { get; set; }
    }
}
