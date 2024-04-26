using OAuch.Compliance;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class TestViewModel {
        public required Test Test { get; set; }
        public required Dictionary<OAuthDocument, TestRequirementLevel> Requirements { get; set; }
    }
}
