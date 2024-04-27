using OAuch.Shared;
using System.Collections.Generic;

namespace OAuch.Compliance.Tests {
    public class TestRun {
        public required bool IsCompleted { get; set; }
        public required IList<OAuthDocument> SelectedDocuments { get; set; }
        public required IList<TestResult> TestResults { get; set; }
        public required TestRunContext Context { get; set; }
    }
}
