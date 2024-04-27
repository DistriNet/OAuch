using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2.Pipeline;
using OAuch.Shared;
using OAuch.Shared.Logging;
using OAuch.Shared.Settings;

namespace OAuch.Protocols.OAuth2 {
    public interface IProvider {
        TestRunContext Context { get; }
        LogContext Log { get; }
        SiteSettings SiteSettings { get; }
        PipelineStage<bool> Pipeline { get; }
        HttpHelper Http { get; }
        string FlowType { get; }
    }
}
