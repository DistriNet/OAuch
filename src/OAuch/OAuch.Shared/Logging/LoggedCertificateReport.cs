using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Logging {
    public class LoggedCertificateReport : LoggedItem {
        public LoggedCertificateReport() {
            this.Content = string.Empty;
        }
        public string Content { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }
}
