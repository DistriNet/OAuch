using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Unity;

namespace OAuch.Shared.Logging {
    public class LogContext : LoggedItem {
        public LogContext() {
            this.Children = [];
        }

        public virtual IList<LoggedItem> Children { get; set; }

        public virtual void Log(string? message, LoggedStringTypes type = LoggedStringTypes.Info) {
            this.Children.Add(new LoggedString(message ?? string.Empty, type));
        }
        public virtual void Log<T>(T item) where T : notnull {
            if (item is string) {
                Log(item as string, LoggedStringTypes.Info);
                return;
            }

            var converter = ServiceLocator.Resolve<ILogConverter<T>>();
            if (converter != null) {
                this.Children.Add(converter.Convert(item));
            } else {
                Debug.WriteLine($"Cannot convert log type '{ typeof(T).FullName }'");
#if DEBUG
                Debugger.Break();
#endif
                Log(item.ToString(), LoggedStringTypes.Debug);
            }
        }

        public override void Accept(ILogVisitor formatter) {}

        public static LogContext NullLogger => new NullLogContext();

        private class NullLogContext : LogContext {
            public override IList<LoggedItem> Children => [];
            public override void Log(string? message, LoggedStringTypes type = LoggedStringTypes.Info) {}
            public override void Log<T>(T item) {}
        }
    }
}