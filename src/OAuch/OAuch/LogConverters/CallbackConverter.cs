using OAuch.Shared.Logging;
using OAuch.TestRuns;

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
