using OAuch.Shared.Interfaces;

namespace OAuch.TestRuns {
    public class CallbackResult : ICallbackResult {
        public CallbackResult(string url, string form) {
            this.Url = url;
            this.FormData = form;
        }

        public string Url { get; }

        public string FormData { get; }
        public override string ToString() {
            if (FormData != null && FormData.Length > 0) {
                return Url + "\r\n\r\n" + FormData;
            }
            return Url;
        }
    }
}
