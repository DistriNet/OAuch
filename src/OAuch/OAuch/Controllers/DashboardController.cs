using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore.Migrations;
using Newtonsoft.Json;
using OAuch.Compliance;
using OAuch.Compliance.Results;
using OAuch.Compliance.Tests;
using OAuch.Compliance.Tests.Shared;
using OAuch.Database;
using OAuch.Database.Entities;
using OAuch.Helpers;
using OAuch.Hubs;
using OAuch.Protocols.OAuth2;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Logging;
using OAuch.Shared.Settings;
using OAuch.TestRuns;
using OAuch.ViewModels;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.WebSockets;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace OAuch.Controllers {
    [Authorize]
    public class DashboardController : BaseController {
        public DashboardController(OAuchDbContext db, IHubContext<TestRunHub> hubContext) {
            this.HubContext = hubContext;
            this.Database = db;
        }
        private IHubContext<TestRunHub> HubContext { get; }
        private OAuchDbContext Database { get; }

        //public IActionResult Paper() {
        //    var model = new DashboardViewModel();
        //    FillMenu(model);

        //    model.SiteResults = GetSiteResults();

        //    var cftests = model.SiteResults.Select(c => c.Result.AllResults.FirstOrDefault(t => t.TestId == "OAuch.Compliance.Tests.Features.CodeFlowSupportedTest")).Where(r => r != null);
        //    var jwts = cftests.Select(c => c.TestLog.Children.OfType<LoggedJwt>().FirstOrDefault()).Where(t => t != null).Where(j => j.Content.Contains("\"HS"));


        //    return View(model);
        //}
        public IActionResult Index() {
            var model = new DashboardViewModel();
            FillMenu(model);

            model.SiteResults = GetSiteResults();
            return View(model);
        }
        protected override void Dispose(bool disposing) {
            base.Dispose(disposing);
            this.Database.Dispose();
        }

        public IActionResult AddDemoSite() {
            var settings = new SiteSettings {
                MetadataUri = "https://demo.duendesoftware.com/.well-known/openid-configuration",
                AuthorizationUri = "https://demo.duendesoftware.com/connect/authorize",
                TokenUri = "https://demo.duendesoftware.com/connect/token",
                CallbackUri = OAuchHelper.CallbackUri,
                JwksUri = "https://demo.duendesoftware.com/.well-known/openid-configuration/jwks",
                RevocationUri = "https://demo.duendesoftware.com/connect/revocation",
                DefaultClient = new ClientSettings {
                    ClientId = "interactive.confidential",
                    ClientSecret = "secret",
                    Scope = "openid profile api offline_access"
                },
                AlternativeClient = new ClientSettings {
                    ClientId = "interactive.confidential.short",
                    ClientSecret = "secret",
                    Scope = "openid profile api offline_access"
                },
                TestUri = "https://demo.duendesoftware.com/api/test",
                TestMethod = HttpMethodsEnum.Get,
                ClientAuthenticationMechanism = ClientAuthenticationMechanisms.ClientSecretBasic,
                OpenIdIssuer = "https://demo.duendesoftware.com",
                PKCEDefault = PKCESupportTypes.Hash,
                ResponseMode = ResponseModes.Default,
                Overrides = new List<GrantOverride> {
                    new GrantOverride {
                        FlowType = OAuthHelper.CLIENT_CREDENTIALS_FLOW_TYPE,
                        OverrideSettings = new ClientSettings {
                            Scope = "api"
                        }
                    }
                },
                SelectedStandards = ComplianceDatabase.AllDocuments.Where(d => d.DocumentCategory != DocumentCategories.Other).Select(d => d.Id).ToList(),
                ExcludedFlows = new List<string> {
                    OAuthHelper.TOKEN_FLOW_TYPE,
                    OAuthHelper.IDTOKEN_TOKEN_FLOW_TYPE,
                    OAuthHelper.IDTOKEN_FLOW_TYPE,
                    OAuthHelper.CODE_IDTOKEN_FLOW_TYPE,
                    OAuthHelper.CODE_IDTOKEN_TOKEN_FLOW_TYPE,
                    OAuthHelper.CODE_TOKEN_FLOW_TYPE,
                    OAuthHelper.DEVICE_FLOW_TYPE,
                    OAuthHelper.PASSWORD_FLOW_TYPE
                }
            };

            var site = new Site {
                SiteId = Guid.NewGuid(),                 
                Name = "Demo Site",
                OwnerId = this.OAuchInternalId!.Value,
                CurrentConfigurationJson = OAuchJsonConvert.Serialize(settings, Formatting.Indented),
                LatestResultId = null
            };
            Database.Sites.Add(site);
            Database.SaveChanges();        
            return RedirectToAction("Index", "Dashboard");
        }


        public IActionResult AddSite() {
            var model = new AddSiteViewModel();
            FillMenu(model, pageType: PageType.AddSite);
            return View(model);
        }

        private bool IsSiteNameOk(string? name) {
            if (name == null || name.Length == 0 || name.Length > 20)
                return false;
            var r = new Regex(@"^[a-zA-Z0-9._\p{Pd} ]+$");
            return r.IsMatch(name);
        }
        [HttpPost]
        public IActionResult AddSite(AddSiteViewModel model) {
            if (ModelState.IsValid) {
                if (IsSiteNameOk(model.Name)) {
                    OAuthMetaData? metadata = null;
                    if (!string.IsNullOrWhiteSpace(model.MetadataUrl) && Uri.TryCreate(model.MetadataUrl, UriKind.Absolute, out var metadataUri)) {
                        metadata = OAuthMetaData.CreateFromUrl(metadataUri);
                        if (metadata == null)
                            ModelState.AddModelError("NoMetadata", "No OAuth metadata could be found on the given URL. If you do not know the correct metadata URL, you can leave this parameter empty and fill in all the OAuth parameters manually.");
                    }
                    if (ModelState.ErrorCount == 0) {
                        var settings = new SiteSettings();
                        settings.CallbackUri = OAuchHelper.CallbackUri;
                        settings.SelectedStandards = ComplianceDatabase.AllDocuments.Where(d => d.DocumentCategory != DocumentCategories.Other).Select(d => d.Id).ToList();
                        if (metadata != null) { // != null implies that it's valid
                            string? scope = null;
                            if (metadata.ScopesSupported != null) {
                                scope = string.Join(' ', metadata.ScopesSupported);
                            }
                            if (metadata.ResponseModesSupported != null && metadata.ResponseModesSupported.Count > 0) {
                                // make sure the server supports the default response modes
                                bool supportsFragment = metadata.ResponseModesSupported.Contains("fragment");
                                bool supportsQuery = metadata.ResponseModesSupported.Contains("query");
                                if (!supportsFragment || !supportsQuery) {
                                    settings.ResponseMode = ResponseModes.AutoDetect;
                                }
                            }
                            settings.MetadataUri = metadata.MetadataUri;
                            settings.AuthorizationUri = metadata.AuthorizationEndpoint;
                            settings.DeviceAuthorizationUri = metadata.DeviceAuthorizationEndpoint;
                            settings.TokenUri = metadata.TokenEndpoint;
                            settings.RevocationUri = metadata.RevocationEndpoint;
                            settings.DefaultClient.Scope = scope;
                            settings.TestUri = metadata.UserinfoEndpoint;
                            settings.OpenIdIssuer = metadata.Issuer;
                            settings.JwksUri = metadata.JwksUri;

                            if (metadata.CodeChallengeMethodsSupported != null && metadata.CodeChallengeMethodsSupported.Count > 0) {
                                if (metadata.CodeChallengeMethodsSupported.Contains("S256"))
                                    settings.PKCEDefault = PKCESupportTypes.Hash;
                                else if (metadata.CodeChallengeMethodsSupported.Contains("plain"))
                                    settings.PKCEDefault = PKCESupportTypes.Plain;
                            }

                            if (metadata.TokenEndpointAuthMethodsSupported != null && metadata.TokenEndpointAuthMethodsSupported.Count > 0) {
                                if (metadata.TokenEndpointAuthMethodsSupported.Contains("client_secret_basic"))
                                    settings.ClientAuthenticationMechanism = ClientAuthenticationMechanisms.ClientSecretBasic;
                                else if (metadata.TokenEndpointAuthMethodsSupported.Contains("client_secret_post"))
                                    settings.ClientAuthenticationMechanism = ClientAuthenticationMechanisms.ClientSecretPost;
                                else if (metadata.TokenEndpointAuthMethodsSupported.Contains("client_secret_jwt"))
                                    settings.ClientAuthenticationMechanism = ClientAuthenticationMechanisms.ClientSecretJwt;
                                else if (metadata.TokenEndpointAuthMethodsSupported.Contains("private_key_jwt"))
                                    settings.ClientAuthenticationMechanism = ClientAuthenticationMechanisms.PrivateKeyJwt;
                            }

                            //if (metadata.RequestParameterSupported != null && metadata.RequestParameterSupported.Value) {
                            //    settings.UseRequestParameter = true;
                            //}
                        }
                        var site = new Site() {
                            SiteId = Guid.NewGuid(),
                            Name = model.Name,
                            OwnerId = this.OAuchInternalId!.Value,
                            CurrentConfigurationJson = OAuchJsonConvert.Serialize(settings, Formatting.Indented),
                            LatestResultId = null
                        };
                        Database.Sites.Add(site);
                        Database.SaveChanges();
                        return RedirectToAction("Settings", new { id = site.SiteId });
                    }
                } else {
                    ModelState.AddModelError("BadChars", "The name you have entered contains invalid characters.");
                }
            }
            FillMenu(model, pageType: PageType.AddSite);
            return View(model);
        }
        public async Task<IActionResult> DeleteSite(Guid id) {
            var site = GetSite(id);
            if (site == null)
                return NotFound();

            var runningManagers = TestRunManager.Current.Where(c => c.SiteId == id).ToList();
            if (runningManagers.Count > 0) {
                foreach(var man in runningManagers) {
                    man.OnAbort();
                }
                for(int retry = 0; retry < 10; retry++) { // use at most 1 second
                    await Task.Delay(100); // wait 100 ms
                    if (!TestRunManager.Current.Any(trm => trm.SiteId == id))
                        break; // some test runs haven't been complete yet
                }
            }
            Database.SerializedTestRuns.RemoveRange(Database.SerializedTestRuns.Where(str => str.SiteId == id));
            Database.Sites.Remove(site);
            Database.SaveChanges();

            return RedirectToAction("Index");
        }

        public IActionResult Overview(Guid id) {
            var site = GetSite(id);
            if (site == null)
                return NotFound();
            if (site.LatestResultId != null)
                return RedirectToAction("Results", new { id = id });
            var model = new OverviewViewModel();
            FillMenu(model, site, PageType.Overview);
            model.SiteId = site.SiteId;
            model.SiteName = site.Name;
            try {
                var settings = OAuchJsonConvert.Deserialize<SiteSettings>(site.CurrentConfigurationJson);
                model.AuthorizationUri= string.IsNullOrWhiteSpace(settings.AuthorizationUri) ? SettingsStatus.Empty : SettingsStatus.Ok; ;
                model.TokenUri= string.IsNullOrWhiteSpace(settings.TokenUri) ? SettingsStatus.Incomplete : SettingsStatus.Ok; ;
                model.ClientId= string.IsNullOrWhiteSpace(settings.DefaultClient.ClientId) ? SettingsStatus.Incomplete : SettingsStatus.Ok; ;
                model.ClientSecret = settings.IsConfidentialClient ? SettingsStatus.Ok : SettingsStatus.Empty;
                model.TestUri = string.IsNullOrWhiteSpace(settings.TestUri) ? SettingsStatus.Incomplete : SettingsStatus.Ok;
                model.SelectedDocuments = settings.SelectedStandards?.Count ?? 0;
            } catch { }
            return View(model);
        }

        public IActionResult Settings(Guid id) {
            var site = GetSite(id);
            if (site == null)
                return NotFound();

            // create the model
            var settings = OAuchJsonConvert.Deserialize<SiteSettings>(site.CurrentConfigurationJson);
            if (settings.Overrides == null)
                settings.Overrides = new List<GrantOverride>();
            foreach (var f in OAuthHelper.AllFlows) {
                if (!settings.Overrides.Any(go => go.FlowType == f))
                    settings.Overrides.Add(new GrantOverride() { FlowType = f });
            }
            var model = new SettingsViewModel(settings);
            model.SiteName = site.Name;
            model.Certificates = new SelectList(Database.Certificates.Where(c => c.OwnerId == this.OAuchInternalId!.Value).ToList(), "SavedCertificateId", "Name");
            FillMenu(model, site, PageType.Settings);
            return View(model);
        }
        [HttpPost]
        public IActionResult Settings(Guid id, SettingsViewModel model) {
            var site = GetSite(id);
            if (site == null)
                return NotFound();

            if (IsSiteNameOk( model.SiteName )) {
                site.Name = model.SiteName;
            }
            // check certificate
            if (model.Settings.CertificateId != null) {
                var cert = Database.Certificates.Where(c => c.SavedCertificateId == model.Settings.CertificateId.Value).SingleOrDefault();
                if (cert == null || cert.OwnerId != this.OAuchInternalId!.Value) {
                    model.Settings.CertificateId = null;
                }
            }
            site.CurrentConfigurationJson = OAuchJsonConvert.Serialize(model.Settings, Formatting.None);
            Database.Sites.Update(site);
            Database.SaveChanges();
            return RedirectToAction("Overview", new { id = id });
        }

        public IActionResult RunTest(Guid id) {
            var model = new RunTestViewModel();
            var site = GetSite(id);
            if (site == null)
                return NotFound();

            model.SiteId = site.SiteId;
            FillMenu(model, site);
            return View(model);
        }
        public IActionResult Running(Guid id) {
            var site = GetSite(id);
            if (site == null)
                return NotFound();

            var manager = TestRunManager.CreateManager(site, HubContext);
            var model = new RunningViewModel();
            model.SiteId = site.SiteId;
            model.TestId = manager.ManagerId;
            FillMenu(model, site);
            return View(model);
        }
        public IActionResult Resume(Guid id /* test result id */, string? retry = null /* test ID to retry */) {
            var serializedTestRun = Database.SerializedTestRuns.FirstOrDefault(c => c.TestResultId == id);
            if (serializedTestRun == null)
                return NotFound();

            var site = Database.Sites.FirstOrDefault(s => s.SiteId == serializedTestRun.SiteId);
            if (site == null || site.OwnerId != this.OAuchInternalId)
                return NotFound();

            IEnumerable<string>? retryIds = null;
            if (retry != null) {
                retryIds = new string[] { retry };
            }

            var manager = TestRunManager.CreateManager(serializedTestRun, site.OwnerId, HubContext, retryIds);
            return RedirectToAction("Running", new { id = site.SiteId });
        }

        public IActionResult Results(Guid id, Guid? rid = null) {
            var site = GetSite(id);
            if (site == null)
                return NotFound();
            if (rid == null)
                rid = site.LatestResultId;

            var serializedTestRun = Database.SerializedTestRuns.FirstOrDefault(tr => tr.TestResultId == rid);
            if (serializedTestRun == null || serializedTestRun.SiteId != site.SiteId /* user tries to access a result of someone else */)
                return RedirectToAction("Overview", new { id = id });

            var model = new ResultsViewModel {
                SiteId = id,
                ResultId = rid!.Value,
                StartedAt = serializedTestRun.StartedAt,
                Result = GetSiteResults(serializedTestRun),
                History = Database.SerializedTestRuns.Where(tr => tr.SiteId == id).OrderByDescending(h => h.StartedAt).Select(tr => new HistoryEntry {
                    HistoryId = tr.TestResultId,
                    When = tr.StartedAt
                })
            };

            FillMenu(model, site, PageType.Results);
            return View(model);
        }
        public IActionResult DeleteResults(Guid id /* siteId */, Guid did /* ResultId to delete from the database */ , Guid? rid = null /* selected ResultId */) {
            var site = GetSite(id);
            if (site == null)
                return NotFound();

            var result = Database.SerializedTestRuns.FirstOrDefault(c => c.TestResultId == did);
            if (result == null || result.SiteId != id) // could not find result, or the user tries to delete someone else's result
                return NotFound();

            // delete the result from the database
            Database.SerializedTestRuns.Remove(result);
            site.LatestResultId = Database.SerializedTestRuns.Where(c => c.SiteId == id && c.TestResultId != did).Select(c => c.TestResultId).FirstOrDefault();
            Database.SaveChanges();

            return RedirectToAction("Results", new { id = id, rid = rid });
        }

        public IActionResult Log(Guid id /* result id */) {
            var serializedTestRun = Database.SerializedTestRuns.FirstOrDefault(tr => tr.TestResultId == id);
            if (serializedTestRun == null)
                return NotFound();
            var site = GetSite(serializedTestRun.SiteId);
            if (site == null)
                return NotFound();

            var testResults = OAuchJsonConvert.Deserialize<List<TestResult>>(serializedTestRun.TestResultsJson);
            var formatter = new HtmlLogFormatter();
            var model = new LogViewModel(formatter.ToHtml(id, testResults));
            return View(model);
        }
        public IActionResult Attacks(Guid id /* result id */) {
            var serializedTestRun = Database.SerializedTestRuns.FirstOrDefault(tr => tr.TestResultId == id);
            if (serializedTestRun == null)
                return NotFound();
            var site = GetSite(serializedTestRun.SiteId);
            if (site == null)
                return NotFound();

            var testResults = OAuchJsonConvert.Deserialize<List<TestResult>>(serializedTestRun.TestResultsJson);
            var results = GetSiteResults(serializedTestRun);
            var model = new AttacksViewModel();
            model.AttackReport = results.AttackReport;
            model.ThreatReports = results.ThreatReports.ToDictionary(c => c.Threat.Id);
            return View(model);
        }

        [NonAction]
        private Site? GetSite(Guid id) {
            var site = Database.Sites.FirstOrDefault(c => c.SiteId == id);
            if (site == null || site.OwnerId != this.OAuchInternalId)
                return null;
            return site;
        }

        [NonAction]
        private void FillMenu(IMenuInformation vm, Site? site = null, PageType pageType = PageType.Unknown) {
            vm.Sites = Database.Sites.Where(s => s.OwnerId == this.OAuchInternalId).OrderBy(s => s.Name).ToList();
            vm.ActiveSite = site;
            vm.PageType = pageType;
        }

        [NonAction]
        private List<SiteResult> GetSiteResults() {
            var ret = new List<SiteResult>();
            foreach (var site in Database.Sites.Where(c => c.OwnerId == this.OAuchInternalId)) {
                var result = GetSiteResults(site);
                if (result != null) {
                    ret.Add(new SiteResult {
                        SiteId = site.SiteId,
                        SiteName = site.Name,
                        Result = result
                    });
                }
            }
            return ret;
        }

        public IActionResult Certificates() {
            var model = new CertificatesViewModel();
            model.Certificates = this.Database.Certificates.Where(c => c.OwnerId == this.OAuchInternalId!.Value).ToList();
            FillMenu(model, pageType: PageType.Certificates);
            return View(model);
        }
        [HttpPost]
        public IActionResult Certificates(CertificatesViewModel model, IFormFile file) {
            if (file != null && file.Length > 0) {
                byte[] blob;
                using (var s = file.OpenReadStream()) {
                    blob = s.ReadFully();
                }
                var x509Cert = CertificateHelper.GetCertificate(blob, model.Password);
                if (x509Cert == null) {
                    ModelState.AddModelError("PfxError", "Could not find a valid certificate in the uploaded file. Please make sure the file is a valid PKCS#12 file, the password is correct, and the certificate's private key is included in the file.");
                } else {
                    var cert = new SavedCertificate();
                    cert.SavedCertificateId = Guid.NewGuid();
                    cert.OwnerId = this.OAuchInternalId!.Value;
                    string cname = x509Cert.FriendlyName;
                    if (string.IsNullOrEmpty(cname)) {
                        cname = x509Cert.GetNameInfo(X509NameType.SimpleName, false);
                    }
                    if (!string.IsNullOrEmpty(cname)) {
                        cert.Name = $"{ cname } ({ Path.GetFileName(file.FileName) })";
                    } else {
                        cert.Name = Path.GetFileName(file.FileName);
                    }
                    cert.Password = model.Password;
                    using (var s = file.OpenReadStream()) {
                        cert.Blob = s.ReadFully();
                    }
                    x509Cert.Dispose();
                    Database.Certificates.Add(cert);
                    Database.SaveChanges();
                }
            }

            model.Certificates = this.Database.Certificates.Where(c => c.OwnerId == this.OAuchInternalId!.Value).ToList();
            FillMenu(model, pageType: PageType.Certificates);
            return View(model);
        }
        public IActionResult DeleteCertificate(Guid? id) {
            if (id == null)
                return NotFound();

            var sc = Database.Certificates.Where(c => c.SavedCertificateId == id.Value).SingleOrDefault();
            if (sc == null || sc.OwnerId != this.OAuchInternalId!.Value)
                return NotFound();

            Database.Certificates.Remove(sc);
            Database.SaveChanges();

            return RedirectToAction("Certificates");
        }

        [NonAction]
        private ComplianceResult? GetSiteResults(Site site) {
            if (site.LatestResultId == null)
                return null;
            return GetSiteResults(site.LatestResultId.Value);
        }
        [NonAction]
        private ComplianceResult? GetSiteResults(Guid rid) {
            var serializedTestRun = Database.SerializedTestRuns.FirstOrDefault(tr => tr.TestResultId == rid);
            if (serializedTestRun == null)
                return null;
            return GetSiteResults(serializedTestRun);
        }
        [NonAction]
        private ComplianceResult GetSiteResults(SerializedTestRun serializedTestRun) {
            var settings = OAuchJsonConvert.Deserialize<SiteSettings>(serializedTestRun.ConfigurationJson);
            var docIds = OAuchJsonConvert.Deserialize<List<string>>(serializedTestRun.SelectedDocumentIdsJson);
            var documents = docIds.Select(did => ComplianceDatabase.AllDocuments.FirstOrDefault(d => d.Id == did)).Where(c => c != null).Select(c => c!);
            var testResults = OAuchJsonConvert.Deserialize<List<TestResult>>(serializedTestRun.TestResultsJson);
            return new ComplianceResult(serializedTestRun.StartedAt, settings, documents, testResults);
        }
    }
}