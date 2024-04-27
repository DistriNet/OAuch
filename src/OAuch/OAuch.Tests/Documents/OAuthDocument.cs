using System.Collections.Generic;

namespace OAuch.Compliance {
    public class OAuthDocument {
        public required string Id { get; init; }
        public required string Name { get; init; }
        public required string Description { get; init; }
        public required string Url { get; init; }
        public required string IsSupportedTest { get; init; }
        public required bool IsStandard { get; set; }
        public required DocumentCategories DocumentCategory { get; set; }

        public required IList<TestRequirementLevel> Countermeasures { get; init; }
        public required IList<TestRequirementLevel> DeprecatedFeatures { get; init; }
        public IList<Test>? AdditionalTests { get; init; } // tests that are necessary to calculate threat resutls


        public override bool Equals(object? obj) {
            var doc = obj as OAuthDocument;
            return doc switch {
                null => false,
                _ => doc.Id == Id
            };
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