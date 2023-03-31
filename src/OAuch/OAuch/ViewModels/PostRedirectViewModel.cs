using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class PostRedirectViewModel {
        public string PostUrl { get; set; }
        public Dictionary<string, string> FormValues { get; set; }
    }
}
