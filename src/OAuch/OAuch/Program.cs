using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OAuch.Database;
using OAuch.Shared;

namespace OAuch
{
    public class Program
    {
        public static void Main(string[] args) {
#if DEBUG
            Debug.WriteLine("Running on " + RuntimeInformation.FrameworkDescription);
            _certificate = LoadCertificate("oauch.io");
            _certificate ??= LoadCertificate("localhost");
#endif
            SetupExceptionHandling();

            var h = CreateHostBuilder(args).Build();
            ServiceLocator.Configure(h.Services);
            using (var db = new OAuchDbContext()) {
                db.Database.EnsureCreated();
            }
            h.Run();
        }

#if DEBUG
        private static X509Certificate2? LoadCertificate(string subject) {
            var cert = LoadCertificate(subject, StoreLocation.CurrentUser);
            cert ??= LoadCertificate(subject, StoreLocation.LocalMachine);
            return cert;
        }
        private static X509Certificate2? LoadCertificate(string subject, StoreLocation location) {
            try {
                using var store = new X509Store(StoreName.My, location);
                store.Open(OpenFlags.ReadOnly);
                var certificate = store.Certificates.Find(
                    X509FindType.FindBySubjectName,
                    subject, false);

                if (certificate.Count == 0) {
                    return null;
                }
                return certificate[0];
            } catch {
                return null;
            }
        }
        private static X509Certificate2? _certificate;
#endif

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder => {
                    webBuilder.UseStartup<Startup>();
#if DEBUG
                    if (_certificate != null)
                        webBuilder.UseKestrel(options => options.ConfigureEndpointDefaults(listenOptions => listenOptions.UseHttps(_certificate)));
#endif
                });

        private static void SetupExceptionHandling() {

            AppDomain.CurrentDomain.UnhandledException += (s, e) => {
                HandleException(e.ExceptionObject as Exception, e.IsTerminating);
            };
            //AppDomain.CurrentDomain.FirstChanceException += (sender, eventArgs) =>
            //{
            //    HandleException(eventArgs.Exception, false);
            //};
            TaskScheduler.UnobservedTaskException += (s, e) => HandleException(e.Exception, false);
        }
        private static void HandleException(Exception? e, bool isTerminating) {
            Debug.WriteLine(e?.ToString());
            Debug.WriteLine($"Is terminating? {isTerminating}");
        }
    }
}
