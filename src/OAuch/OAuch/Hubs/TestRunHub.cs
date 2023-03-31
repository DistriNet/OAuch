using Microsoft.AspNetCore.SignalR;
using OAuch.Compliance;
using OAuch.Compliance.Tests;
using OAuch.Controllers;
using OAuch.Shared.Enumerations;
using OAuch.TestRuns;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.Hubs {
    public class TestRunHub : Hub {
        private TestRunManager? FindManager(string managerId) {
            if (Guid.TryParse(managerId, out var managerGuid)) {
                var manager = TestRunManager.ManagerById(managerGuid);
                if (manager == null)
                    return null;

                Guid? oauchInternalId = null;
                var user = this.Context.User;
                if (user != null) {
                    var claim = user.FindFirst("https://oauch.io/internalid");
                    if (claim != null && Guid.TryParseExact(claim.Value, "N", out var internalId)) {
                        oauchInternalId = internalId;
                    }
                }
                if (oauchInternalId == null)
                    return null;

                if (manager.OwnerId == oauchInternalId.Value) // make sure the user is accessing a test that he owns
                    return manager;

                return manager;
            }
            return null;
        }

        public async Task OnReady(string managerId) {
            var manager = FindManager(managerId);
            if (manager == null) {
                await TestRunConnection.SendError(this.ClientProxy, "The specified test ID could not be found. Please restart the testing process.");
                return;
            }
            await manager.Connection.AddConnection(this.Context.ConnectionId);
            await manager.StartTests(this.ClientProxy);
            await manager.ResendFeatures(this.Context.ConnectionId); // send all the features that are detected to the browser (useful when resuming a session or when a new browser window connects)
        }
        public async Task OnCallback(string managerId, string href, string form) {
            var manager = FindManager(managerId);
            if (manager == null) {
                await TestRunConnection.SendError(this.ClientProxy, "The specified test ID could not be found. Please restart the testing process.");
                return;
            }
            await manager.OnCallback(href, form);
        }
        public async Task OnCancel(string managerId) {
            var manager = FindManager(managerId);
            if (manager == null) {
                await TestRunConnection.SendError(this.ClientProxy, "The specified test ID could not be found. Please restart the testing process.");
                return;
            }
            await manager.OnCancel();
        }
        public async Task OnAbort(string managerId) {
            var manager = FindManager(managerId);
            if (manager == null) {
                await TestRunConnection.SendError(this.ClientProxy, "The specified test ID could not be found. Please restart the testing process.");
                return;
            }
            await manager.OnAbort();
        }
        private IClientProxy ClientProxy {
            get {
                return this.Clients.Client(this.Context.ConnectionId);
            }
        }
    }

    public class TestRunConnection {
        public TestRunConnection(IHubContext<TestRunHub> hubContext, string groupName) {
            this.HubContext = hubContext;
            this.GroupName = groupName;
        }

        private IHubContext<TestRunHub> HubContext { get; }
        private string GroupName { get; }
        private IClientProxy Proxy {
            get {
                return this.HubContext.Clients.Groups(GroupName);
            }
        }

        public Task AddConnection(string connectionId) => this.HubContext.Groups.AddToGroupAsync(connectionId, this.GroupName);

        public Task SendFeatureDetected(string name, bool available) => SendFeatureDetected(Proxy, name, available);
        public Task SendFeatureDetected(string connectionId, string name, bool available) => SendFeatureDetected(this.HubContext.Clients.Client(connectionId), name, available);
        private Task SendFeatureDetected(IClientProxy proxy, string name, bool available) => proxy.SendAsync("OnFeatureDetected", name, available);

        public Task SendFinished(string message) => Proxy.SendAsync("OnFinished", message);
        public Task SendMessage(string message) => Proxy.SendAsync("OnMessage", message);
        public Task SendProgress(int newValue) => Proxy.SendAsync("OnProgress", newValue);
        public Task SendNewTestStarted(string testId) => Proxy.SendAsync("OnNewTestStarted", testId);
        public async Task ReportTest(TestResult testResult) {
            if (testResult.Outcome == null)
                return;
            string cls;
            //if (instance.Parent.GetWeight(instance.Settings.Profile) == TestWeight.None) {
            //    cls = "inf";
            //} else {
            //    cls = instance.Succeeded.Value ? "ok" : "nok";
            //}
            switch (testResult.Outcome) {
                case TestOutcomes.SpecificationFullyImplemented:
                case TestOutcomes.SpecificationPartiallyImplemented:
                    cls = "ok";
                    break;
                case TestOutcomes.SpecificationNotImplemented:
                case TestOutcomes.Failed:
                    cls = "nok";
                    break;
                case TestOutcomes.Skipped:
                    cls = "inf";
                    break;
                default:
                    Debugger.Break(); // hmmm
                    cls = "nok";
                    break;
            }
            var test = ComplianceDatabase.Tests[testResult.TestId];
            await SendMessage($"{ test.Title }: <span class=\"{ cls }\">{ test.ResultFormatter.Format(testResult.Outcome) }</span>");
        }
        public Task EnableCancel() => EnableCancel(Proxy);
        public Task RedirectPopup(string url, bool cancelable) => RedirectPopup(Proxy, url, cancelable);
        public Task SendError(string message) => SendError(Proxy, message);
        public static Task RedirectPopup(IClientProxy proxy, string url, bool cancelable) {
            var redirect = proxy.SendAsync("RedirectPopup", url);
            if (cancelable)
                return EnableCancel(proxy).ContinueWith(t => redirect);
            return redirect;
        }
        public static Task SendError(IClientProxy proxy, string message) => proxy.SendAsync("OnError", message);
        public static Task EnableCancel(IClientProxy proxy) => proxy.SendAsync("OnEnableCancel");
    }
}