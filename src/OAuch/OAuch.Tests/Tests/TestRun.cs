using Newtonsoft.Json;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests {
    public class TestRun {
        public required bool IsCompleted { get; set; }
        public required IList<OAuthDocument> SelectedDocuments { get; set; }
        public required IList<TestResult> TestResults { get; set; }
        public required TestRunContext Context { get; set; }
    }
}
