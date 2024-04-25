using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Logging {
    public class LoggedTest : LogContext {
        public LoggedTest() {
            this.TestId = "MISSING";
        }
        public string TestId { get; set; }
        public bool HasThrown { get; set; }
        public TestOutcomes? Outcome { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}
