using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class PostRedirectViewModel {
        public required string PostUrl { get; set; }
        public required Dictionary<string, string> FormValues { get; set; }
    }
}
