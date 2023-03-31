using OAuch.Compliance;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.ViewModels {
    public class TestViewModel {
        public Test Test { get; set; }
        public Dictionary<OAuthDocument, TestRequirementLevel> Requirements { get; set; }
    }
}
