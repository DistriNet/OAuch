using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance {
    public class OAuthDocument {
        public string Id { get; init; }
        public string Name { get; init; }
        public string Description { get; init; }
        public string Url { get; init; }
        public string IsSupportedTest { get; init; }
        public bool IsStandard { get; set; }
        public DocumentCategories DocumentCategory { get; set; }

        public IList<TestRequirementLevel> Countermeasures { get; init; }
        public IList<TestRequirementLevel> DeprecatedFeatures { get; init; }
        public IList<Test>? AdditionalTests { get; init; } // tests that are necessary to calculate threat resutls


        public override bool Equals(object? obj) {
            var doc = obj as OAuthDocument;
            if (doc == null)
                return false;
            return doc.Id == this.Id;
        }
        public override int GetHashCode() {
            return this.Id.GetHashCode();
        }
    }
    public enum DocumentCategories : int { 
        OAuth2,
        OpenIDConnect,
        Draft,
        Other
    }
}