using System.Collections.Generic;

namespace OAuch.Compliance {
    public class Threat {
        public required string Id { get; init; }
        public required string Title { get; init; }
        public required string Description { get; init; }
        // what are the assumptions for the vulnerability
        public required OAuthDocument Document { get; init; }
        public required string LocationInDocument { get; init; }
        public required List<ThreatInstance> Instances { get; init; }
        public string? AliasOf { get; init; } //used for BCP threats that are an alias of threats in RFC6819
        public required List<>
    }
    public class TestCombination : List<Test> {
        // this represents an AND-list of tests
        // ALL tests must (partially) succeed (or skipped - this means the test is irrelevant)
    }
    public class ThreatInstance {
        public string? ExtraDescription { get; init; }
        public required List<Test> DependsOnFeatures { get; init; } // if any of these tests (partially) succeeds, the vulnerability is considered relevant
        public required List<TestCombination> MitigatedBy { get; init; } // if any of these tests (partially) succeeds, the vulnerability is considered (partially) mitigated
    }
}
