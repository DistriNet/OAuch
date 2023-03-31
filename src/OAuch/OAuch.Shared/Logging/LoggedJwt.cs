using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Logging {
    public class LoggedJwt : LoggedItem {
        public string Content { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}
