using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Logging {
    public class LoggedHttpResponse : LoggedItem {
        public int StatusCode { get; set; }
        public string Response { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}
