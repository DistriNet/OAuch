using OAuch.Shared.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.LogConverters {
    public class RedirectConverter : ILogConverter<RedirectConverter.RedirectInfo> {
        public LoggedItem Convert(RedirectInfo item) {
            return new LoggedRedirect() {
                 Url = item.Url
            };
        }

        public class RedirectInfo {
            public string Url { get; set; }
        }
    }
}
