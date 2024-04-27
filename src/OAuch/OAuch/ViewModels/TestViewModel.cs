using OAuch.Compliance;
using System.Collections.Generic;

namespace OAuch.ViewModels {
    public class TestViewModel {
        public required Test Test { get; set; }
        public required Dictionary<OAuthDocument, TestRequirementLevel> Requirements { get; set; }
    }
}
