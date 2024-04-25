using OAuch.Compliance.Tests.ApiEndpoint;
using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.OAuth2;
using OAuch.Shared.Enumerations;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace OAuch.Compliance.Tests {
    /// <summary>
    /// When a TestResult of a test case is renamed (or removed) and it is still referenced in the JSon results in the database,
    /// the json cannot be deserialized anymore (because the corresponding TestResult class cannot be found). When this occurs,
    /// the referenced TestResult will be replaced with this dummy result instead.
    /// </summary>
    public class DummyTestResult : TestResult {
        public DummyTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(DummyTestImplementation);
    }
    public class DummyTestImplementation : TestImplementation {
        public DummyTestImplementation(TestRunContext context, DummyTestResult result) : base(context, result) { }
#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        public override async Task Run() {
            // This is a dummy test implementation that should never be run by OAuch
            Debugger.Break();
            throw new NotSupportedException();
        }
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
    }
}
