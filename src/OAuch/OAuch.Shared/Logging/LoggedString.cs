using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Logging {
    public class LoggedString : LoggedItem {
        public LoggedString() : this(string.Empty, LoggedStringTypes.Info) { }
        public LoggedString(string content) : this(content, LoggedStringTypes.Info) { }
        public LoggedString(string content, LoggedStringTypes type) {
            this.Content = content;
            this.StringType = type;
        }

        public string Content { get; set; }
        public LoggedStringTypes StringType { get; set; }

        public override void Accept(ILogVisitor formatter) {
            formatter.Visit(this);
        }
    }

    public enum LoggedStringTypes { 
        Info = 1,
        Warning = 2,
        Debug = 3
    }
}
