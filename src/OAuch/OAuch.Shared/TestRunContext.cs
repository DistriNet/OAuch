using OAuch.Shared.Interfaces;
using OAuch.Shared.Logging;
using OAuch.Shared.Settings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared {
    public record TestRunContext(Guid ManagerId, IBrowser Browser, LogContext Log, StateCollection State, SiteSettings SiteSettings) { }
}
