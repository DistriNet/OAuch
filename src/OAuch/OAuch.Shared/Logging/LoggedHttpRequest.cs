using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Logging {
    public class LoggedHttpRequest : LoggedItem {
        public LoggedHttpRequest() {
            this.Method = string.Empty;
            this.Url = string.Empty;
            this.Request = string.Empty;
        }
        public string Method { get; set; }
        public string Url { get; set; }
        public string Request { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}
