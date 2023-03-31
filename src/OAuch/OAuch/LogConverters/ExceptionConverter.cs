using OAuch.Shared.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.LogConverters {
    public class ExceptionConverter : ILogConverter<Exception> {
        public LoggedItem Convert(Exception item) {
            LoggedException? inner = null;
            if (item.InnerException != null)
                inner = Convert(item.InnerException) as LoggedException;

            return new LoggedException() {
                Message = item.Message,
                StackTrace = item.StackTrace,
                InnerException = inner
            };
        }
    }
}
