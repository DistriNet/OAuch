using Newtonsoft.Json;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests {
    public class TestRun {
        public bool IsCompleted { get; set; }
        public IList<OAuthDocument> SelectedDocuments { get; set; }
        public IList<TestResult> TestResults { get; set; }
        public TestRunContext Context { get; set; }
    }
}
