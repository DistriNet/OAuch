using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Logging {
    public class LoggedCallback : LoggedItem {
        public LoggedCallback() {
            this.Url = string.Empty;
            this.FormData = string.Empty;
        }
        public string Url { get; set; }
        public string FormData { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}
