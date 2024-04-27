using Microsoft.AspNetCore.SignalR;
using OAuch.Compliance;
using OAuch.Compliance.Tests;
using OAuch.Database;
using OAuch.Database.Entities;
using OAuch.Helpers;
using OAuch.Hubs;
using OAuch.Shared;
using OAuch.Shared.Logging;
using OAuch.Shared.Settings;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.TestRuns {
    public class TestRunManager {
        public TestRunManager(Site site, IHubContext<TestRunHub> hubContext) {
            this.ManagerId = Guid.NewGuid();
            this.CreatedAt = DateTime.Now;
            this.OwnerId = site.OwnerId;
            this.SiteId = site.SiteId;
            this.Connection = new TestRunConnection(hubContext, this.ManagerId.ToString("N"));
            this.Log = new RelayLogContext();
            var stateCollection = new StateCollection();
            this.Browser = new Browser(this.Log, this.Connection, stateCollection);
            var settings = OAuchJsonConvert.Deserialize<SiteSettings>(site.CurrentConfigurationJson) ?? throw new InvalidDataException("Could not deserialize data.");
            var documents = settings.SelectedStandards?.Select(did => ComplianceDatabase.AllDocuments.FirstOrDefault(d => d.Id == did)).Where(d => d != null).Cast<OAuthDocument>().ToList(); //ComplianceDatabase.AllDocuments.ToList();
            if (documents == null || documents.Count == 0)
                documents = [.. ComplianceDatabase.AllDocuments]; // should we keep this or not?
            var testResults = CreateEmptyResults(documents);
            this.TestRun = new TestRun {
                IsCompleted = false,
                Context = new TestRunContext(
                    this.ManagerId,
                    this.Browser,
                    this.Log,
                    stateCollection,
                    settings),
                SelectedDocuments = documents,
                TestResults = testResults
            };
            _isSaved = false; // it is not yet saved in the database
        }
        public TestRunManager(SerializedTestRun serializedTestRun, Guid ownerId, IHubContext<TestRunHub> hubContext, IEnumerable<string>? retryIds) {
            this.ManagerId = serializedTestRun.TestResultId;
            this.CreatedAt = serializedTestRun.StartedAt;
            this.SiteId = serializedTestRun.SiteId;
            this.OwnerId = ownerId;
            this.Connection = new TestRunConnection(hubContext, this.ManagerId.ToString("N"));
            this.Log = new RelayLogContext();
            var stateCollection = OAuchJsonConvert.Deserialize<StateCollection>(serializedTestRun.StateCollectionJson);
            var settings = OAuchJsonConvert.Deserialize<SiteSettings>(serializedTestRun.ConfigurationJson);
            var docIds = OAuchJsonConvert.Deserialize<List<string>>(serializedTestRun.SelectedDocumentIdsJson);
            if (stateCollection == null || settings == null || docIds == null)
                throw new InvalidDataException("Could not deserialize data.");
            this.Browser = new Browser(this.Log, this.Connection, stateCollection);
            var documents = docIds.Select(did => ComplianceDatabase.AllDocuments.FirstOrDefault(d => d.Id == did)).Where(d => d != null).ToList();
            var testResults = OAuchJsonConvert.Deserialize<List<TestResult>>(serializedTestRun.TestResultsJson);
            testResults = CreateEmptyResults(documents, testResults); // this adds empty results for tests that were not implemented when the serialized test run was executed
            ClearRetries(testResults, retryIds);
            this.TestRun = new TestRun {
                IsCompleted = !testResults.Any(tr => tr.Outcome == null),
                Context = new TestRunContext(
                    this.ManagerId,
                    this.Browser,
                    this.Log,
                    stateCollection,
                    settings),
                SelectedDocuments = documents!,
                TestResults = testResults
            };

            _isSaved = true; // this test run is already present in the database
        }

        private static void ClearRetries(List<TestResult> testResults, IEnumerable<string>? retryIds) {
            if (retryIds == null)
                return;

            foreach (var retryId in retryIds) {
                var testResult = testResults.Where(tr => tr.TestId == retryId).FirstOrDefault();
                if (testResult != null) {
                    testResult.Outcome = null;
                    testResult.TestLog?.Children.Clear();
                }
            }
        }

        /// <summary>
        /// This method checks if new test implementations have been added since this test run was executed,
        /// and if such implementations are found they are added to the test run.        
        /// </summary>        
        private static List<TestResult> CreateEmptyResults(IEnumerable<OAuthDocument?> documents, List<TestResult>? oldResults = null) {
            List<TestResult> resultsList;
            if (oldResults == null)
                resultsList = [];
            else
                resultsList = oldResults;
            var resultTypesList = resultsList.Select(tr => tr.GetType()).ToList();
            // add all the tests from the OAuth documents
            foreach (var doc in documents) {
                if (doc != null) {
                    AddTest(ComplianceDatabase.Tests[doc.IsSupportedTest]);
                    AddTests(doc.Countermeasures.Select(c => c.Test));
                    AddTests(doc.DeprecatedFeatures.Select(c => c.Test));
                    if (doc.AdditionalTests != null)
                        AddTests(doc.AdditionalTests);
                }
            }
            return resultsList;

            void AddTests(IEnumerable<Test> tests) {
                foreach (var testRL in tests) {
                    AddTest(testRL);
                }
            }
            void AddTest(Test test) {
                if (resultTypesList.Contains(test.ResultType))
                    return; // the test has already been added to the list

                var emptyResult = test.CreateEmptyResult();
                var dependencies = emptyResult.Dependencies;
                // make sure all the dependencies are present
                foreach (var dep in dependencies) {
                    var depTest = ComplianceDatabase.FindTestByResultType(dep);
                    if (depTest != null) {
                        AddTest(depTest);
                    } else {
                        Debugger.Break(); // this means we are dependent on a TestResult for which no parent Test exists
                    }
                }
                resultsList.Add(emptyResult);
                resultTypesList.Add(test.ResultType);
            }
        }

        public async Task ResendFeatures(string connectionId) {
            var list = this.Context.State.Get<Dictionary<string, bool>>(StateKeys.FeatureCache);
            foreach (var item in list) {
                await this.Browser.SendFeatureDetected(connectionId, item.Key, item.Value);
            }
        }

        public Task StartTests(IClientProxy client) {
            if (this.HasStarted) {
                // a new browser window reconnected to an already running test suite
                var callback = this.Browser.CurrentCallback;
                if (callback != null)
                    return TestRunConnection.RedirectPopup(client, callback, true);
            } else {
                this.HasStarted = true;
                Task.Run(() => InternalStartTests()); // the tests are run in a new thread (otherwise we block SignalR)
            }
            return Task.CompletedTask;
        }
        private async Task InternalStartTests() {
            // get a list of individual tests that are excluded            
            //var et = Enumerable.Empty<string>();
            //if (!string.IsNullOrWhiteSpace(Context.SiteSettings.ExcludeTests)) {
            //    et = Context.Site.Settings.ExcludeTests.Split(',');
            //}
            //var excludedTests = new SortedSet<string>(et);

            //// get a list of the test categories that are excluded
            //var excludedCategories = new SortedSet<TestCategories>();
            //if (Context.Site.Settings.ExcludeHttp) excludedCategories.Add(TestCategories.Http);
            //if (Context.Site.Settings.ExcludeAuthorizationCodeFlow) excludedCategories.Add(TestCategories.AuthorizationCodeFlow);
            //if (Context.Site.Settings.ExcludeClientCredentialsFlow) excludedCategories.Add(TestCategories.ClientCredentialsFlow);
            //if (Context.Site.Settings.ExcludeDeviceCodeFlow) excludedCategories.Add(TestCategories.DeviceFlow);
            //if (Context.Site.Settings.ExcludeImplicitFlow) excludedCategories.Add(TestCategories.ImplicitFlow);
            //if (Context.Site.Settings.ExcludePasswordFlow) excludedCategories.Add(TestCategories.PasswordFlow);
            //if (Context.Site.Settings.ExcludeTestAPI) excludedCategories.Add(TestCategories.Tokens);

            int tested = 0;
            foreach (var tr in TestRun.TestResults) {
                if (tr.Outcome == null) {  // we haven't run the test yet
                    Debug.WriteLine("Now running test: " + tr.TestId);
                    this.Log.RelayContext = tr.TestLog;
                    await Connection.SendNewTestStarted(Shorten(tr.TestId));
                    await tr.Run(this.TestRun);
                    await Connection.ReportTest(tr);
                }
                tested++;
                await Connection.SendProgress(tested * 100 / TestRun.TestResults.Count);
                if (_isCanceled)
                    break;
            }
            if (!_isCanceled)
                TestRun.IsCompleted = true;

            // save test run
            var serializedTestRun = new SerializedTestRun {
                TestResultId = ManagerId,
                SiteId = SiteId,
                StartedAt = CreatedAt,
                ConfigurationJson = OAuchJsonConvert.Serialize(TestRun.Context.SiteSettings),
                SelectedDocumentIdsJson = OAuchJsonConvert.Serialize(TestRun.SelectedDocuments.Select(d => d.Id)),
                TestResultsJson = OAuchJsonConvert.Serialize(TestRun.TestResults),
                StateCollectionJson = OAuchJsonConvert.Serialize(TestRun.Context.State)
            };
            using (var db = new OAuchDbContext()) {
                if (_isSaved) {
                    db.SerializedTestRuns.Update(serializedTestRun);
                } else {
                    db.SerializedTestRuns.Add(serializedTestRun);
                }
                var site = db.Sites.FirstOrDefault(s => s.SiteId == this.SiteId);
                if (site != null) {
                    site.LatestResultId = this.ManagerId;
                    db.Sites.Update(site);
                }
                await db.SaveChangesAsync();
            }

            await Connection.SendFinished($"All tests completed");

            RemoveManager(this.ManagerId);

            static string Shorten(string id) {
                int index = id.LastIndexOf('.');
                if (index >= 0) {
                    return id[(index + 1)..];
                } else {
                    return id;
                }
            }
        }
        public Task OnCallback(string href, string form) {
            this.Browser.ProcessCallback(href, form);
            return Task.CompletedTask;
        }
        public async Task OnCancel() {
            await Context.Browser.RedirectPopup("/Callback/Skipped", false);
            this.Browser.CancelCallback();
        }
        public Task OnAbort() {
            _isCanceled = true;
            this.Browser.CancelCallback();
            return Task.CompletedTask;
        }


        private RelayLogContext Log { get; }
        public Browser Browser { get; }
        private TestRun TestRun { get; }
        public Guid ManagerId { get; }
        public Guid SiteId { get; }
        public Guid OwnerId { get; }
        public TestRunContext Context => TestRun.Context;
        public DateTime CreatedAt { get; }
        public TestRunConnection Connection { get; }
        public bool HasStarted { get; private set; }
        private bool _isCanceled;
        private readonly bool _isSaved;

        public static TestRunManager CreateManager(Site site, IHubContext<TestRunHub> hubContext) {
            lock (_managers) {
                TestRunManager? manager = _managers.Values.FirstOrDefault(m => m.SiteId == site.SiteId);
                manager ??= new TestRunManager(site, hubContext);
                _managers[manager.ManagerId] = manager;
                return manager;
            }
        }
        public static TestRunManager CreateManager(SerializedTestRun serializedTestRun, Guid ownerId, IHubContext<TestRunHub> hubContext, IEnumerable<string>? retryIds = null) {
            lock (_managers) {
                TestRunManager manager;
                if (_managers.TryGetValue(serializedTestRun.TestResultId, out TestRunManager? value)) {
                    manager = value;
                } else {
                    manager = new TestRunManager(serializedTestRun, ownerId, hubContext, retryIds);
                    _managers[manager.ManagerId] = manager;
                }
                return manager;
            }
        }
        public static void RemoveManager(Guid id) {
            lock (_managers) {
                _managers.Remove(id);
            }
        }
        public static IList<TestRunManager> Current {
            get {
                IList<TestRunManager> ret;
                lock (_managers) {
                    ret = [.. _managers.Values];
                }
                return ret;
            }
        }
        public static TestRunManager? ManagerById(Guid id) {
            lock (_managers) {
                if (_managers.TryGetValue(id, out TestRunManager? value))
                    return value;
            }
            return null;
        }
        private static readonly Dictionary<Guid, TestRunManager> _managers = [];
    }
}
