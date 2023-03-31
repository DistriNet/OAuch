using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Logging {
    public class LoggedHttpRequest : LoggedItem {
        public string Method { get; set; }
        public string Url { get; set; }
        public string Request { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}
