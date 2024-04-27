using OAuch.Shared.Interfaces;
using OAuch.Shared.Logging;
using OAuch.Shared.Settings;
using System;

namespace OAuch.Shared {
    public record TestRunContext(Guid ManagerId, IBrowser Browser, LogContext Log, StateCollection State, SiteSettings SiteSettings) { }
}
