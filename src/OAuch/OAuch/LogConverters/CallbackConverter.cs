using OAuch.Shared.Logging;
using OAuch.TestRuns;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.LogConverters {
    public class CallbackConverter : ILogConverter<CallbackResult> {
        public LoggedItem Convert(CallbackResult item) {
            return new LoggedCallback() {
                FormData = item.FormData,
                Url = item.Url
            };
        }
    }
}
