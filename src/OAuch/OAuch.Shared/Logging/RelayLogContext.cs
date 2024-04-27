using System;
using System.Collections.Generic;

namespace OAuch.Shared.Logging {
    public class RelayLogContext : LogContext {
        public LogContext? RelayContext {
            get; set;
        }

        public override DateTime CreatedAt => RelayContext?.CreatedAt ?? DateTime.Now;
        public override IList<LoggedItem> Children => RelayContext?.Children ?? [];

        public override void Log(string? message, LoggedStringTypes type = LoggedStringTypes.Info) {
            RelayContext?.Log(message, type);
        }
        public override void Log<T>(T item) {
            RelayContext?.Log<T>(item);
        }
    }
}
