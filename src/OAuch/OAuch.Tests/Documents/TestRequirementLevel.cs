using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance {
    public class TestRequirementLevel {
        public Test Test { get; init; }
        public RequirementLevels RequirementLevel { get; init; }
        public string LocationInDocument { get; init; }
    }
    public class DocumentTestRequirementLevel {
        public DocumentTestRequirementLevel(OAuthDocument doc, TestRequirementLevel trl) {
            this.Document = doc;
            this.TestRequirementLevel = trl;
        }
        public OAuthDocument Document { get; set; }
        public TestRequirementLevel TestRequirementLevel { get; set; }
    }
}
