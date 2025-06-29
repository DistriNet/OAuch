﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.SignalR;
using Newtonsoft.Json;
using OAuch.Compliance;
using OAuch.Compliance.Results;
using OAuch.Compliance.Tests;
using OAuch.Database;
using OAuch.Database.Entities;
using OAuch.Helpers;
using OAuch.Hubs;
using OAuch.OAuthThreatModel.Attackers;
using OAuch.OAuthThreatModel.Flows;
using OAuch.Protocols.OAuth2;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using OAuch.Shared.Settings;
using OAuch.TestRuns;
using OAuch.ViewModels;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace OAuch.Controllers {
    [Authorize]
    public partial class DashboardController : BaseController {

        private static readonly Dictionary<string, (string Title, IEnumerable<OAuthDocument> Documents)> _initialDocuments = new() {
            //{ "OAUTH21", ("OAuth 2.1 (default)", [ComplianceDatabase.Documents[""]]) },
            { "OAUTH20BCP", ("OAuth 2.0 (with Best Practices)", [ComplianceDatabase.Documents["RFC6749"], ComplianceDatabase.Documents["RFC6750"], ComplianceDatabase.Documents["RFC6819"], ComplianceDatabase.Documents["SecBCP"], ComplianceDatabase.Documents["RFC7636"]]) },
            { "OAUTH20", ("OAuth 2.0 (original standard, outdated)", [ComplianceDatabase.Documents["RFC6749"], ComplianceDatabase.Documents["RFC6750"], ComplianceDatabase.Documents["RFC6819"]]) },
            { "OIDC", ("OpenID Connect + OAuth 2.0", [ComplianceDatabase.Documents["OIDC"], ComplianceDatabase.Documents["RFC6749"], ComplianceDatabase.Documents["RFC6750"], ComplianceDatabase.Documents["RFC6819"]]) },
            { "FAPIBASE", ("Financial-grade API 1.0 (base profile)", [ComplianceDatabase.Documents["FAPI1Base"], ComplianceDatabase.Documents["OIDC"], ComplianceDatabase.Documents["RFC6749"], ComplianceDatabase.Documents["RFC6750"], ComplianceDatabase.Documents["RFC6819"]]) },
            { "FAPIADV", ("Financial-grade API 1.0 (advanced profile)", [ComplianceDatabase.Documents["FAPI1Adv"], ComplianceDatabase.Documents["FAPI1Base"], ComplianceDatabase.Documents["OIDC"], ComplianceDatabase.Documents["RFC6749"], ComplianceDatabase.Documents["RFC6750"], ComplianceDatabase.Documents["RFC6819"]]) },
            { "ALL",  ("All available tests", ComplianceDatabase.AllDocuments) },
        };
        private const string _defaultInitialDocuments = "OAUTH20BCP";

        public DashboardController(OAuchDbContext db, IHubContext<TestRunHub> hubContext) {
            this.HubContext = hubContext;
            this.Database = db;
        }
        private IHubContext<TestRunHub> HubContext { get; }
        private OAuchDbContext Database { get; }

        public IActionResult Index() {
            var model = new DashboardViewModel {
                SiteResults = GetSiteResults()
            };
            FillMenu(model);
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
                Overrides = [
                    new GrantOverride {
                        FlowType = OAuthHelper.CLIENT_CREDENTIALS_FLOW_TYPE,
                        OverrideSettings = new ClientSettings {
                            Scope = "api"
                        }
                    }
                ],
                SelectedStandards = ComplianceDatabase.AllDocuments.Select(d => d.Id).ToList(), //.Where(d => d.DocumentCategory != DocumentCategories.Other)
                ExcludedFlows = [
                    OAuthHelper.TOKEN_FLOW_TYPE,
                    OAuthHelper.IDTOKEN_TOKEN_FLOW_TYPE,
                    OAuthHelper.IDTOKEN_FLOW_TYPE,
                    OAuthHelper.CODE_IDTOKEN_FLOW_TYPE,
                    OAuthHelper.CODE_IDTOKEN_TOKEN_FLOW_TYPE,
                    OAuthHelper.CODE_TOKEN_FLOW_TYPE,
                    OAuthHelper.DEVICE_FLOW_TYPE,
                    OAuthHelper.PASSWORD_FLOW_TYPE
                ]
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

        public IActionResult Import() {
            var model = new EmptyViewModel();
            FillMenu(model, pageType: PageType.Import);
            return View(model);
        }
        [HttpPost]
        public IActionResult Import(IFormFile file) {
            if (file != null && file.Length > 0) {
                byte[]? blob = null;
                if (file.FileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) {
                    using (var s = file.OpenReadStream()) {
                        using (var zip = new ZipArchive(s, ZipArchiveMode.Read)) {
                            var entry = zip.Entries.FirstOrDefault();
                            if (entry != null) {
                                using (var stream = entry.Open()) {
                                    blob = stream.ReadFully();
                                }
                            }
                        }
                    }
                } else {
                    using (var s = file.OpenReadStream()) {
                        blob = s.ReadFully();
                    }
                }

                SiteData[]? o = null;
                if (blob != null) {
                    var json = Encoding.UTF8.GetString(blob);
                    o = OAuchJsonConvert.Deserialize<SiteData[]>(json);
                }
                if (o != null) {
                    foreach (var s in o) {
                        if (s.Name == null || s.CurrentConfiguration == null) // invalid data
                            continue;
                        // add the certificate
                        if (s.Certificate != null) {
                            var cer = new SavedCertificate() {
                                OwnerId = this.OAuchInternalId!.Value,
                                Name = s.Certificate.Name,
                                Password = s.Certificate.Password,
                                Blob = s.Certificate.Blob
                            };
                            Database.Certificates.Add(cer);
                            Database.SaveChanges(); // get the CertificateId
                            s.CurrentConfiguration.CertificateId = cer.SavedCertificateId;
                        }
                        // add the site
                        var site = new Site() {
                            Name = s.Name,
                            OwnerId = this.OAuchInternalId!.Value,
                            CurrentConfigurationJson = OAuchJsonConvert.Serialize(s.CurrentConfiguration),
                            LatestResultId = null
                        };
                        Database.Sites.Add(site);
                        Database.SaveChanges(); // save to get a SiteId
                        // add the serialized tests
                        SerializedTestRun? mostRecent = null;
                        if (s.TestRuns != null) {
                            foreach (var tr in s.TestRuns) {
                                var str = new SerializedTestRun {
                                    SiteId = site.SiteId,
                                    StartedAt = tr.StartedAt,
                                    ConfigurationJson = OAuchJsonConvert.Serialize(tr.Configuration),
                                    SelectedDocumentIdsJson = OAuchJsonConvert.Serialize(tr.SelectedDocumentIds),
                                    TestResultsJson = OAuchJsonConvert.Serialize(tr.TestResults),
                                    StateCollectionJson = OAuchJsonConvert.Serialize(tr.StateCollection)
                                };
                                if (mostRecent == null || mostRecent.StartedAt < str.StartedAt)
                                    mostRecent = str;
                                Database.SerializedTestRuns.Add(str);
                            }
                        }
                        Database.SaveChanges(); // get the Id of the most recent test run
                        if (mostRecent != null) {
                            site.LatestResultId = mostRecent.TestResultId;
                            Database.SaveChanges();
                        }
                    }
                    return RedirectToAction("Index");
                } else {
                    ModelState.AddModelError("DeserializeError", "Could not deserialize the input file.");
                }
            }
            var model = new EmptyViewModel();
            FillMenu(model, pageType: PageType.Import);
            return View(model);
        }
        public IActionResult Export(Guid id) {
            var site = GetSite(id);
            if (site == null)
                return NotFound();
            var model = new EmptyViewModel();
            FillMenu(model, site, PageType.Export);
            return View(model);
        }
        public IActionResult ExportData(Guid id) {
            var site = GetSite(id);
            if (site == null)
                return NotFound();
            var data = GetSiteData(site);
            var jsonData = Encoding.UTF8.GetBytes(OAuchJsonConvert.Serialize(new SiteData[] { data }, Formatting.Indented));
            return File(jsonData, "application/json", "export.json");
        }
        public IActionResult ExportAll() {
            var model = new EmptyViewModel();
            FillMenu(model, null, PageType.ExportAll);
            return View(model);
        }
        [HttpPost]
        public IActionResult ExportAllData(Guid[]? SelectedSites) {
            if (SelectedSites == null || SelectedSites.Length == 0)
                return new EmptyResult();

            var sites = new List<SiteData>();
            foreach(var guid in SelectedSites) {
                var site = GetSite(guid);
                if (site == null)
                    return NotFound(); // if one of the GUID's is invalid, cancel the entire operation (hack in progress?)
                sites.Add(GetSiteData(site));
            }
            var jsonData = Encoding.UTF8.GetBytes(OAuchJsonConvert.Serialize(sites, Formatting.Indented));
            var zippedData = new MemoryStream();
            using (var archive = new ZipArchive(zippedData, ZipArchiveMode.Create, true)) {
                var exportEntry = archive.CreateEntry("export.json");
                using (var exportStream = exportEntry.Open()) {
                    exportStream.Write(jsonData);
                }
            }
            zippedData.Position = 0;

            return File(zippedData, "application/json", "export.zip");
        }
        [NonAction]
        private SiteData GetSiteData(Site site) {
            var currentConfig = JsonConvert.DeserializeObject<SiteSettings>(site.CurrentConfigurationJson);
            CertificateInfo? certificate = null;
            if (currentConfig?.CertificateId != null) {
                var c = Database.Certificates.FirstOrDefault(c => c.SavedCertificateId == currentConfig.CertificateId);
                if (c != null) {
                    certificate = new CertificateInfo {
                        Name = c.Name,
                        Password = c.Password,
                        Blob = c.Blob
                    };
                }
            }
            var runs = Database.SerializedTestRuns.Where(c => c.SiteId == site.SiteId).Select(c => new TestRunData {
                StartedAt = c.StartedAt,
                SelectedDocumentIds = OAuchJsonConvert.Deserialize<List<string>>(c.SelectedDocumentIdsJson)!,
                Configuration = OAuchJsonConvert.Deserialize<SiteSettings>(c.ConfigurationJson)!,
                TestResults = OAuchJsonConvert.Deserialize<List<TestResult>>(c.TestResultsJson)!,
                StateCollection = OAuchJsonConvert.Deserialize<StateCollection>(c.StateCollectionJson)!
            }).ToList();

            return new SiteData {
                Name = site.Name,
                CurrentConfiguration = currentConfig!,
                Certificate = certificate,
                TestRuns = runs
            };
        }

        private class SiteData {
            public string? Name { get; set; }
            public SiteSettings? CurrentConfiguration { get; set; }
            public CertificateInfo? Certificate { get; set; }
            public List<TestRunData>? TestRuns { get; set; }
        }
        private class TestRunData {
            public required DateTime StartedAt { get; set; }
            public required List<string> SelectedDocumentIds { get; set; }
            public required SiteSettings Configuration { get; set; }
            public required List<TestResult> TestResults { get; set; }
            public required StateCollection StateCollection { get; set; }
        }
        private class CertificateInfo {
            public required string Name { get; set; }
            public string? Password { get; set; }
            public required byte[] Blob { get; set; }
        }

        public IActionResult AddSite() {
            var model = new AddSiteViewModel();
            FillMenu(model, pageType: PageType.AddSite);
            model.InitialDocuments = _initialDocuments;
            model.SelectedInitialDocuments = _defaultInitialDocuments;
            return View(model);
        }
        private static bool IsSiteNameOk([NotNullWhen(true)] string? name) {
            if (name == null || name.Length == 0 || name.Length > 20)
                return false;
            var r = IsSiteNameOkRegEx();
            return r.IsMatch(name);
        }
        [HttpPost]
        public IActionResult AddSite(AddSiteViewModel model) {
            if (ModelState.IsValid) {
                if (!_initialDocuments.Keys.Any(c => c == model.SelectedInitialDocuments)) 
                    model.SelectedInitialDocuments = _defaultInitialDocuments;               

                if (IsSiteNameOk(model.Name)) {
                    OAuthMetaData? metadata = null;
                    if (!string.IsNullOrWhiteSpace(model.MetadataUrl) && Uri.TryCreate(model.MetadataUrl, UriKind.Absolute, out var metadataUri)) {
                        metadata = OAuthMetaData.CreateFromUrl(metadataUri);
                        if (metadata == null)
                            ModelState.AddModelError("NoMetadata", "No OAuth metadata could be found on the given URL. If you do not know the correct metadata URL, you can leave this parameter empty and fill in all the OAuth parameters manually.");
                    }
                    if (ModelState.ErrorCount == 0) {
                        var settings = new SiteSettings {
                            CallbackUri = OAuchHelper.CallbackUri,
                            SelectedStandards = _initialDocuments[model.SelectedInitialDocuments].Documents.Select(c => c.Id).ToList() //ComplianceDatabase.AllDocuments.Select(d => d.Id).ToList() //.Where(d => d.DocumentCategory != DocumentCategories.Other)
                        };
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
                            settings.ParUri = metadata.PushedAuthorizationRequestEndpoint;

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
            model.InitialDocuments = _initialDocuments;
            return View(model);
        }
        public async Task<IActionResult> DeleteSite(Guid id) {
            var site = GetSite(id);
            if (site == null)
                return NotFound();

            var runningManagers = TestRunManager.Current.Where(c => c.SiteId == id).ToList();
            if (runningManagers.Count > 0) {
                foreach (var man in runningManagers) {
                    await man.OnAbort();
                }
                for (int retry = 0; retry < 10; retry++) { // use at most 1 second
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
                return RedirectToAction("Results", new { id });
            var model = new OverviewViewModel {
                SiteId = site.SiteId,
                SiteName = site.Name
            };
            FillMenu(model, site, PageType.Overview);
            //try {
            var settings = OAuchJsonConvert.Deserialize<SiteSettings>(site.CurrentConfigurationJson);
            if (settings == null)
                return NotFound();
            model.AuthorizationUri = string.IsNullOrWhiteSpace(settings.AuthorizationUri) ? SettingsStatus.Empty : SettingsStatus.Ok; ;
            model.TokenUri = string.IsNullOrWhiteSpace(settings.TokenUri) ? SettingsStatus.Incomplete : SettingsStatus.Ok; ;
            model.ClientId = string.IsNullOrWhiteSpace(settings.DefaultClient.ClientId) ? SettingsStatus.Incomplete : SettingsStatus.Ok; ;
            model.ClientSecret = settings.IsConfidentialClient ? SettingsStatus.Ok : SettingsStatus.Empty;
            model.TestUri = string.IsNullOrWhiteSpace(settings.TestUri) ? SettingsStatus.Incomplete : SettingsStatus.Ok;
            model.SelectedDocuments = settings.SelectedStandards?.Count ?? 0;
            //} catch { }
            return View(model);
        }

        public IActionResult Settings(Guid id) {
            var site = GetSite(id);
            if (site == null)
                return NotFound();

            // create the model
            var settings = OAuchJsonConvert.Deserialize<SiteSettings>(site.CurrentConfigurationJson);
            if (settings == null)
                return NotFound();
            settings.Overrides ??= [];
            foreach (var f in OAuthHelper.AllFlows) {
                if (!settings.Overrides.Any(go => go.FlowType == f))
                    settings.Overrides.Add(new GrantOverride() { FlowType = f });
            }
            var model = new SettingsViewModel(settings) {
                SiteName = site.Name,
                Certificates = new SelectList(Database.Certificates.Where(c => c.OwnerId == this.OAuchInternalId!.Value).ToList(), "SavedCertificateId", "Name")
            };
            FillMenu(model, site, PageType.Settings);
            return View(model);
        }
        [HttpPost]
        public IActionResult Settings(Guid id, SettingsViewModel model) {
            var site = GetSite(id);
            if (site == null)
                return NotFound();

            if (IsSiteNameOk(model.SiteName)) {
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
            return RedirectToAction("Overview", new { id });
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
            var model = new RunningViewModel {
                SiteId = site.SiteId,
                TestId = manager.ManagerId
            };
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
                retryIds = [retry];
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
                return RedirectToAction("Overview", new { id });

            var currentSiteSettings = OAuchJsonConvert.Deserialize<SiteSettings>(site.CurrentConfigurationJson);
            if (currentSiteSettings == null)
                return NotFound();

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
            model.SettingsChanged = serializedTestRun.ConfigurationJson != site.CurrentConfigurationJson;
            
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

            return RedirectToAction("Results", new { id, rid });
        }

        public IActionResult Log(Guid id /* result id */) {
            var serializedTestRun = Database.SerializedTestRuns.FirstOrDefault(tr => tr.TestResultId == id);
            if (serializedTestRun == null)
                return NotFound();
            var site = GetSite(serializedTestRun.SiteId);
            if (site == null)
                return NotFound();

            var testResults = OAuchJsonConvert.Deserialize<List<TestResult>>(serializedTestRun.TestResultsJson);
            if (testResults == null)
                return NotFound();
            var formatter = new HtmlLogFormatter();
            var model = new LogViewModel(HtmlLogFormatter.ToHtml(id, testResults));
            return View(model);
        }
        public IActionResult Attacks(AttacksViewModel filter) {
            var model = GetAttacks(filter);
            if (model == null)
                return NotFound();
            return PartialView(model);
        }
        public IActionResult AttackList(AttacksViewModel filter) {
            var model = GetAttacks(filter);
            if (model == null)
                return NotFound();
            return PartialView(model);
        }
        [NonAction]
        private AttacksViewModel? GetAttacks(AttacksViewModel filter) {
            var serializedTestRun = Database.SerializedTestRuns.FirstOrDefault(tr => tr.TestResultId == filter.Id);
            if (serializedTestRun == null)
                return null;
            var site = GetSite(serializedTestRun.SiteId);
            if (site == null)
                return null;

            var testResults = OAuchJsonConvert.Deserialize<List<TestResult>>(serializedTestRun.TestResultsJson);
            if (testResults == null)
                return null;
            var results = GetSiteResults(serializedTestRun);
            var context = new ThreatModelContext(testResults, results.ThreatReports);
            var model = new AttacksViewModel {
                Id = filter.Id,
                ThreatReports = results.ThreatReports.ToDictionary(c => c.Threat.Id),
                AllFlows = Flow.All.Where(c => c.IsRelevant(context)).ToList(),
                AttackerTypes = AttackerTypes.All
            };
            var allThreats = OAuthThreatModel.Threats.Threat.All.Where(c => c.IsRelevant(context)).DistinctBy(c => c.Id).ToList();
            model.AllUnmitigatedThreats = allThreats.Where(c => {
                if (!model.ThreatReports.TryGetValue(c.Id, out var tr))
                    return false;
                return tr.Outcome == TestOutcomes.SpecificationNotImplemented && tr.Threat.AliasOf == null;
            }).ToList();
            model.AllPartialThreats = allThreats.Where(c => {
                if (!model.ThreatReports.TryGetValue(c.Id, out var tr))
                    return false;
                return tr.Outcome == TestOutcomes.SpecificationPartiallyImplemented && tr.Threat.AliasOf == null;
            }).ToList();

            if (filter?.SelectedFilter != null) {
                model.SelectedFilter = filter.SelectedFilter;
            } else {
                var allSelected = new List<string>();
                allSelected.AddRange(model.AllFlows.Select(c => c.Id));
                allSelected.AddRange(model.AllUnmitigatedThreats.Select(c => c.Id));
                allSelected.AddRange(model.AllPartialThreats.Select(c => c.Id)); // By default we do not consider partial threats
                allSelected.AddRange(model.AttackerTypes.Select(c => c.Id));
                model.SelectedFilter = allSelected;
            }

            model.AttackReport = results.GetAttackReport(model.SelectedFilter, context);

            return model;
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
            vm.Sites = [.. Database.Sites.Where(s => s.OwnerId == this.OAuchInternalId).OrderBy(s => s.Name)];
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
            var model = new CertificatesViewModel {
                Certificates = [.. this.Database.Certificates.Where(c => c.OwnerId == this.OAuchInternalId!.Value)]
            };
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
                    var cert = new SavedCertificate {
                        SavedCertificateId = Guid.NewGuid(),
                        OwnerId = this.OAuchInternalId!.Value
                    };
                    string cname = x509Cert.FriendlyName;
                    if (string.IsNullOrEmpty(cname)) {
                        cname = x509Cert.GetNameInfo(X509NameType.SimpleName, false);
                    }
                    if (!string.IsNullOrEmpty(cname)) {
                        cert.Name = $"{cname} ({Path.GetFileName(file.FileName)})";
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

            model.Certificates = [.. this.Database.Certificates.Where(c => c.OwnerId == this.OAuchInternalId!.Value)];
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
        private static ComplianceResult GetSiteResults(SerializedTestRun serializedTestRun) {
            var settings = OAuchJsonConvert.Deserialize<SiteSettings>(serializedTestRun.ConfigurationJson);
            var docIds = OAuchJsonConvert.Deserialize<List<string>>(serializedTestRun.SelectedDocumentIdsJson);
            var testResults = OAuchJsonConvert.Deserialize<List<TestResult>>(serializedTestRun.TestResultsJson);
            if (settings == null || docIds == null || testResults == null)
                throw new InvalidDataException("Unable to deserialize site data.");
            var documents = docIds.Select(did => ComplianceDatabase.AllDocuments.FirstOrDefault(d => d.Id == did)).Where(c => c != null).Select(c => c!);
            return new ComplianceResult(serializedTestRun.StartedAt, settings, documents, testResults);
        }

        [GeneratedRegex(@"^[a-zA-Z0-9._\p{Pd} ]+$")]
        private static partial Regex IsSiteNameOkRegEx();
    }
}