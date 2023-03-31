using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

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
