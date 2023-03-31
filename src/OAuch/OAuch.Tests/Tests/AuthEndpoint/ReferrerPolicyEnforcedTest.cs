using AngleSharp;
using AngleSharp.Html.Parser;
using OAuch.Compliance.Tests.Features;
using OAuch.Protocols.Http;
using OAuch.Protocols.OAuth2;
using OAuch.Protocols.OAuth2.BuildingBlocks;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance.Tests.AuthEndpoint {
    public class ReferrerPolicyEnforcedTest : Test {
        public override string Title => "Does the server suppress the referrer";
        public override string Description => "This test checks whether the server suppresses the 'Referer' header by applying the appropriate referrer policy";
        public override string? TestingStrategy => "";
        public override TestResultFormatter ResultFormatter => TestResultFormatter.YesGoodNoBad;
        public override Type ResultType => typeof(ReferrerPolicyEnforcedTestResult);
    }
    public class ReferrerPolicyEnforcedTestResult : TestResult {
        public ReferrerPolicyEnforcedTestResult(string testId) : base(testId) { }
        public override Type ImplementationType => typeof(ReferrerPolicyEnforcedTestImplementation);
    }
    public class ReferrerPolicyEnforcedTestImplementation : TestImplementation {
        public ReferrerPolicyEnforcedTestImplementation(TestRunContext context, ReferrerPolicyEnforcedTestResult result, HasSupportedFlowsTestResult flows) : base(context, result, flows) { }

        public async override Task Run() {
            var flows = GetDependency<HasSupportedFlowsTestResult>(true);
            if (flows == null) {
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var provider = flows.CreateProviderWithStage<SendAuthorizationRedirect, string, ICallbackResult?>(this.Context);
            if (provider == null) {
                LogInfo("No working flow that uses the authorization endpoint could be found");
                Result.Outcome = TestOutcomes.Skipped;
                return;
            }

            var url = Http.GetFullUrl(Context.SiteSettings.AuthorizationUri!);
            var request = HttpRequest.CreateGet(url);
            request.AllowAutoRedirect = true;
            var response = await Http.SendRequest(request);

            var header = response.Headers.Get("Referrer-Policy");
            if (header != null) {
                if (header.IndexOf(',') >= 0) {
                    var allHeaders = header.Split(',');
                    header = allHeaders[allHeaders.Length - 1]; // uses a comma-separated list with the desired policy specified last
                }
                header = header.Trim();
                // the server specifies a referrer policy; see if it's configured correctly
                var safeHeaders = new string[] { "no-referrer", "origin", "origin-when-cross-origin", "same-origin", "strict-origin-when-cross-origin" };
                Result.Outcome = safeHeaders.Any(sh => header == sh) ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
                if (Result.Outcome == TestOutcomes.SpecificationNotImplemented) {
                    LogInfo("A referrer policy was specified in an HTTP header, but it was not acceptable.", "one of: " + string.Join(", ", safeHeaders), header);
                }
                return;
            }
            // no referrer policy header could be found; let's see if we find it in the HTML
            var htmlContents = response.ToString(true);
            var context = BrowsingContext.New(Configuration.Default);
            var parser = context.GetService<IHtmlParser>();
            var document = parser.ParseDocument(htmlContents);
            var metaTags = document.QuerySelectorAll("meta");
            foreach (var metaTag in metaTags) {
                if (metaTag?.Attributes["name"]?.Value == "referrer") {
                    var value = metaTag.Attributes["content"]?.Value;
                    var safeMetas = new string[] { "never", "origin" };
                    Result.Outcome = safeMetas.Any(sm => value == sm) ? TestOutcomes.SpecificationFullyImplemented : TestOutcomes.SpecificationNotImplemented;
                    if (Result.Outcome == TestOutcomes.SpecificationFullyImplemented) {
                        LogInfo("A referrer policy was specified as an HTML meta tag, but it was not acceptable.", "one of: " + string.Join(", ", safeMetas), value);
                    }
                    return;
                }
            }
            LogInfo("No referrer policy was specified, either as HTTP header or HTML meta tag.");
            Result.Outcome = TestOutcomes.SpecificationNotImplemented;
        }
    }
}
