using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Rewrite;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Helpers {
    public class NonWwwRule : IRule {
        public void ApplyRule(RewriteContext context) {
            var req = context.HttpContext.Request;
            var currentHost = req.Host;
            if (currentHost.Host.StartsWith("www.oauch.io")) {
                var newUrl = new StringBuilder().Append("https://oauch.io").Append(req.PathBase).Append(req.Path).Append(req.QueryString);
                context.HttpContext.Response.Redirect(newUrl.ToString());
                context.Result = RuleResult.EndResponse;
            }
        }
    }
}
