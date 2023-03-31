using Newtonsoft.Json;
using OAuch.Compliance;
using OAuch.Compliance.Tests;
using OAuch.Protocols.Http;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Helpers {
    public class HtmlLogFormatter {
        public HtmlLogFormatter() {
            //
        }

        public string ToHtml(Guid resultId, IEnumerable<TestResult> testResults, bool printVersion = false) {
            var sb = new StringBuilder();
            var visitor = new HtmlVisitor(resultId, sb, printVersion);
            foreach (var e in testResults) {
                e.TestLog.Accept(visitor);
            }
            return sb.ToString();
        }
        public string ToHtml(Guid resultId, TestResult result, bool printVersion = false) {
            var sb = new StringBuilder();
            var visitor = new HtmlVisitor(resultId, sb, printVersion);
            result.TestLog.Accept(visitor);
            return sb.ToString();
        }

        private class HtmlVisitor : ILogVisitor {
            public HtmlVisitor(Guid resultId, StringBuilder output, bool printVersion) {                
                _output = output;
                _printVersion = printVersion;
                _resultId = resultId;
            }
            private StringBuilder _output;
            private bool _printVersion;
            private Guid _resultId;

            public static string CreateInfoBox(string titleText, string messageHtml, string background = "bg-warning", string icon = "fas fa-exclamation-triangle") {
                return $"<div class=\"row justify-content-center\"><div class=\"col-12 col-md-10\"><div class=\"info-box { background }\"><span class=\"info-box-icon\"><i class=\"{ icon }\"></i></span><div class=\"info-box-content\"><p class=\"infotitle\">{ EncodingHelper.HtmlEncode(titleText) }</p><span>{ messageHtml }</span></div></div></div></div>";
            }
            //public static string CreateExpandable(string titleText, string bodyHtml, string cardColor = "card-primary", string icon = "fas fa-cookie") {
            //    return $"<div class=\"row justify-content-center\"><div class=\"col-12 col-md-11\"><div class=\"card { cardColor } collapsed-card\"><div class=\"card-header\"><h3 class=\"card-title\"><i class=\"{ icon }\"></i>&nbsp;&nbsp;&nbsp;{ EncodingHelper.HtmlEncode(titleText) }</h3><div class=\"card-tools\"><button type=\"button\" class=\"btn btn-tool\" data-card-widget=\"collapse\"><i class=\"fas fa-plus\"></i></button></div></div><div class=\"card-body\" style=\"display: none;\">{ bodyHtml }</div></div></div></div>";
            //}
            //public static string CreateSmallBox(string titleText, string messageHtml, string background = "bg-info", string icon = "fas fa-phone-volume") {
            //    return $"<div class=\"row justify-content-center\"><div class=\"col-12 col-md-11\"><div class=\"small-box { background }\"><div class=\"inner\"><h3>{ titleText }</h3>{ messageHtml }</div><div class=\"icon\"><i class=\"{ icon }\"></i></div></div></div></div>";
            //}
            public static string CreateTimelineItem(string titleText, string messageHtml, string background, string icon) {
                return $"<div class=\"tic\"><i class=\"{ icon } { background }\"></i><div class=\"timeline-item\"><h3 class=\"timeline-header { background }\">{ EncodingHelper.HtmlEncode(titleText) }</h3><div class=\"timeline-body\">{ messageHtml }</div></div></div>";
            }
            public static string CreateTimelineItem(string titleText, string background, string icon) {
                return $"<div class=\"tic\"><i class=\"{ icon } { background }\"></i><div class=\"timeline-item\"><h3 class=\"timeline-header { background }\">{ EncodingHelper.HtmlEncode(titleText) }</h3></div></div>";
            }
            public static string CreateTimelineHeader(string titleText, string background) {
                return $"<div class=\"time-label\"><span class=\"{ background }\">{ EncodingHelper.HtmlEncode(titleText) }</span></div>";
            }

            //public override void VisitAuthorizationCode(AuthorizationCodeLogEntry e) {
            //    _output.Append(CreateTimelineItem("Authorization code result", "<pre>" + EncodingHelper.HtmlEncode(e.Content) + "</pre>", "bg-warning", "fas fa-cookie"));
            //}

            public void Visit(LoggedCallback e) {
                string postData;
                if (e.FormData == "")
                    postData = "The request did not contain POST parameters.";
                else
                    postData = $"The request contained the following post parameters: <code>{ EncodingHelper.HtmlEncode(e.FormData) }</code>";
                _output.Append(CreateTimelineItem("Callback received", $"<p>A callback was received from the OAuth provider at the URL <code>{ EncodingHelper.HtmlEncode(e.Url) }</code></p><p>{ postData }</p>", "bg-gray", "fas fa-phone-volume"));
            }

            public void Visit(LoggedCertificateReport e) {
                _output.Append(CreateTimelineItem("X509 Server Certificate", "<pre>" + e.Content + "</pre>", "bg-maroon", "fas fa-certificate"));
            }

            //public override void VisitDebug(DebugLogEntry e) { }

            public void Visit(LoggedException e) {
                _output.Append(CreateInfoBox("Unexpected error...", GetExceptionDescription(e)));
            }
            private string GetExceptionDescription(LoggedException e) {
                var desc = $"An unexpected error occurred while performing the test. The system returned the message: <em>`{ EncodingHelper.HtmlEncode(e.Message ?? "(none)") }'</em>. The final result of the test may not be correctly determined.";
                if (e.InnerException != null) {
                    StringBuilder messageTrace = new StringBuilder();
                    messageTrace.Append("<br/>");
                    LoggedException? ex = e;
                    var spaces = 0;
                    while (ex != null) {
                        messageTrace.Append("<br/>");
                        if (spaces > 0) {
                            for (int i = 0; i < spaces; i++) {
                                messageTrace.Append("&nbsp;");
                            }
                            messageTrace.Append("&rarr;");
                        }
                        messageTrace.Append(ex.Message);
                        ex = ex.InnerException;
                        spaces += 2;
                    }
                    desc = desc + messageTrace.ToString();
                }
                return desc;
            }

            public  void Visit(LoggedHttpRequest e) {
                var url = e.Url;
                if (url.Length > 90) {
                    url = url.Substring(0, 90) + "…";
                }
                _output.Append(CreateTimelineItem($"HTTP { e.Method } { url }", "<pre>" + EncodingHelper.HtmlEncode(e.Request) + "</pre>", "bg-blue", "fas fa-upload"));
            }

            public void Visit(LoggedHttpResponse e) {
                var statusCode = (HttpStatusCode)e.StatusCode;
                var response = e.Response;
                if (response.Length > 16384 /*&& _printVersion*/) {
                    response = response.Substring(0, 16384) + "… HTTP RESPONSE CLIPPED …";
                }
                _output.Append(CreateTimelineItem($"HTTP { e.StatusCode } { Enum.GetName(typeof(HttpStatusCode), statusCode) }", "<pre>" + EncodingHelper.HtmlEncode(response) + "</pre>", statusCode.IsError() ? "bg-red" : "bg-green", "fas fa-download"));
            }

            public void Visit(LoggedString e) {
                _output.Append(CreateTimelineItem(e.Content, "bg-info", "fas fa-info"));
            }

            public void Visit(LoggedJwks e) {
                _output.Append(CreateTimelineItem("Decoded JSON Web Key Set", "<pre>" + EncodingHelper.HtmlEncode(e.Content) + "</pre>", "bg-warning", "fas fa-key"));
            }

            public void Visit(LoggedJwt e) {
                _output.Append(CreateTimelineItem("Decoded JSON Web Token", "<pre>" + EncodingHelper.HtmlEncode(e.Content) + "</pre>", "bg-warning", "fas fa-cookie"));
            }

            public void Visit(LoggedRedirect e) {
                _output.Append(CreateTimelineItem("Redirecting pop-up", $"<p>The pop-up window is being redirected to <code>{ EncodingHelper.HtmlEncode(e.Url) }</code></p>", "bg-gray", "fas fa-directions"));
            }

            public void Visit(LoggedTest e) {
                string title = e.TestId;
                //string failedDesc = "";
                
                if (e.TestId != null && ComplianceDatabase.Tests.TryGetValue(e.TestId, out var test)) {
                    title = test.Title;

                }

                string collapsible = "";
                if (!_printVersion) {
                    collapsible = $"<div class=\"card collapsed-card\"><div class=\"card-header bg-lightgray\"><div class=\"card-tools leftcardtools\"><button type=\"button\" class=\"btn btn-tool\" data-card-widget=\"collapse\"><i class=\"fas fa-plus\"></i></button></div><h3 class=\"card-title\">Test <strong>`{ HelperMethods.ShortenTestId(e.TestId) }'</strong> [<a href=\"/Dashboard/Resume/{ _resultId }?retry={ e.TestId }\">retry</a>]<br/><em>{ title }?</em></h3></div><div class=\"card-body\" style=\"display: none;\">";
                }
                _output.Append(collapsible + $"<div class=\"timeline\">" + CreateTimelineHeader($"Test `{ HelperMethods.ShortenTestId(e.TestId) }' started", "bg-gray"));
                if (e.Children != null) {
                    foreach (var c in e.Children) {
                        c.Accept(this);
                    }
                }
                string collapsibleEnd;
                if (e.HasThrown) {
                    collapsibleEnd = _printVersion ? "" : "</div></div>";
                    _output.Append(CreateTimelineItem("An unexpected error occurred", "bg-red", "fas fa-bomb")
                        + CreateTimelineHeader($"Test `{ HelperMethods.ShortenTestId(e.TestId) }' finished", "bg-gray")
                        + "</div>" /* timeline */
                        + collapsibleEnd);
                } else {
                    string icon, text, bg, additionalItem = "", ribbon;
                    if (e.Outcome == null) {
                        icon = "fas fa-question";
                        bg = "bg-gray";
                        text = $"Test '{ HelperMethods.ShortenTestId(e.TestId) }' has not been executed yet.";
                        ribbon = "<div class=\"ribbon-wrapper\"><div class=\"ribbon bg-gray\">PLANNED</div></div>";
                    } else if (e.Outcome == TestOutcomes.Failed) {
                        icon = "fas fa-bomb";
                        bg = "bg-gray";
                        text = $"Test '{ HelperMethods.ShortenTestId(e.TestId) }' has crashed while executing.";
                        ribbon = "<div class=\"ribbon-wrapper\"><div class=\"ribbon bg-gray\">CRASHED</div></div>";
                    } else if (e.Outcome == TestOutcomes.Skipped) {
                        icon = "fas fa-question";
                        bg = "bg-gray";
                        text = $"Test '{ HelperMethods.ShortenTestId(e.TestId) }' was skipped because a precondition wasn't met.";
                        ribbon = "<div class=\"ribbon-wrapper\"><div class=\"ribbon bg-gray\">SKIPPED</div></div>";
                    } else if (e.Outcome == TestOutcomes.SpecificationNotImplemented) {
                        icon = "fas fa-times";
                        bg = "bg-red";
                        text = $"Test '{ HelperMethods.ShortenTestId(e.TestId) }' was executed and failed.";
                        //if (failedDesc != "")
                        //    additionalItem = CreateTimelineItem(failedDesc, "bg-info", "fas fa-info");
                        ribbon = "<div class=\"ribbon-wrapper\"><div class=\"ribbon bg-red\">FAILED</div></div>";
                    } else {
                        icon = "fas fa-check";
                        bg = "bg-green";
                        text = $"Test '{ HelperMethods.ShortenTestId(e.TestId) }' was executed and { (e.Outcome == TestOutcomes.SpecificationPartiallyImplemented ? "partially " : "") }succeeded.";
                        ribbon = "<div class=\"ribbon-wrapper\"><div class=\"ribbon bg-green\">SUCCESS</div></div>";
                    }
                    collapsibleEnd = _printVersion ? "" : "</div>" + ribbon + "</div>";
                    _output.Append(CreateTimelineItem(text, bg, icon)
                        + additionalItem
                        + CreateTimelineHeader($"Test `{ HelperMethods.ShortenTestId(e.TestId) }' finished", "bg-gray")
                        + "</div>" /* timeline */
                        + collapsibleEnd);
                }

            }

            public void Visit(LoggedTokenResult e) {
                if ((e.AccessTokens == null || e.AccessTokens.Count == 0) && (e.IdentityTokens == null || e.IdentityTokens.Count == 0)) {
                    _output.Append(CreateTimelineItem("No access tokens or identity tokens have been received from the server.", "bg-info", "fas fa-info"));
                } else {
                    var fo = new TokenFormatObject {
                        AuthorizationCode = e.AuthorizationCode,
                        RefreshToken = e.RefreshToken,
                        AccessTokens = e.AccessTokens,
                        IdentityTokens = e.IdentityTokens
                    };
                    string json = OAuchJsonConvert.Serialize(fo, Formatting.Indented);
                    _output.Append(CreateTimelineItem("Token result", "<pre>" + EncodingHelper.HtmlEncode(json) + "</pre>", "bg-warning", "fas fa-cookie"));
                }
                if (e.Exception != null) {
                    _output.Append(CreateTimelineItem("Token exception...", "<pre>" + EncodingHelper.HtmlEncode(GetExceptionDescription(e.Exception)) + "</pre>", "bg-gray", "fas fa-bomb"));
                }
            }

            private class TokenFormatObject {
                [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
                public string? AuthorizationCode { get; set; }
                [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
                public string? RefreshToken { get; set; }
                [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
                public IList<string>? AccessTokens { get; set; }
                [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
                public IList<string>? IdentityTokens { get; set; }
            }

            //public override void VisitTokenResult(TokenResultLogEntry e) {
            //    _output.Append(CreateTimelineItem("Token result", "<pre>" + EncodingHelper.HtmlEncode(e.Content) + "</pre>", "bg-warning", "fas fa-cookie"));
            //}
        }
    }
}
