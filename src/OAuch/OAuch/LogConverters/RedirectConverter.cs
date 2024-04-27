using OAuch.Shared.Logging;

namespace OAuch.LogConverters {
    public class RedirectConverter : ILogConverter<RedirectConverter.RedirectInfo> {
        public LoggedItem Convert(RedirectInfo item) {
            return new LoggedRedirect() {
                Url = item.Url
            };
        }

        public class RedirectInfo {
            public required string Url { get; set; }
        }
    }
}
