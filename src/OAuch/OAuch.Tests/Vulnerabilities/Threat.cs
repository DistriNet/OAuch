using OAuch.Compliance.Tests;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.WebSockets;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace OAuch.Compliance {
    public class Threat {
        public string Id { get; init; }
        public string Title { get; init; }
        public string Description { get; init; }
        // what are the assumptions for the vulnerability
        public OAuthDocument Document { get; init; }
        public string LocationInDocument { get; init; }
        public List<ThreatInstance> Instances { get; init; }
    }
    public class TestCombination : List<Test> {
        // this represents an AND-list of tests
        // ALL tests must (partially) succeed (or skipped - this means the test is irrelevant)
    }
    public class  ThreatInstance {
        public string? ExtraDescription { get; init; }
        public List<Test> DependsOnFeatures { get; init; } // if any of these tests (partially) succeeds, the vulnerability is considered relevant
        public List<TestCombination> MitigatedBy { get; init; } // if any of these tests (partially) succeeds, the vulnerability is considered (partially) mitigated
    }
}
