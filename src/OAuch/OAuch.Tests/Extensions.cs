using OAuch.Compliance.Tests;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Compliance {
   public static class Extensions {
        public static string Format(this TestOutcomes outcome, TestResultFormatter formatter) {
            switch (outcome) {
                case TestOutcomes.SpecificationFullyImplemented:
                    return formatter.CountermeasureFullyImplemented;
                case TestOutcomes.SpecificationNotImplemented:
                    return formatter.CountermeasureNotImplemented;
                case TestOutcomes.SpecificationPartiallyImplemented:
                    return formatter.CountermeasurePartiallyImplemented;
                case TestOutcomes.Failed:
                    return formatter.Failed;
                case TestOutcomes.Skipped:
                    return formatter.Skipped;
                default:
                    throw new NotSupportedException();
            }
        }
        public static string ToName(this SslProtocols p) {
#pragma warning disable CS0618 // Type or member is obsolete
#pragma warning disable SYSLIB0039 // Type or member is obsolete
            switch (p) {
                case SslProtocols.Ssl2:
                    return "SSL 2.0";
                case SslProtocols.Ssl3:
                    return "SSL 3.0";
                case SslProtocols.Tls:
                    return "TLS 1.0";
                case SslProtocols.Tls11:
                    return "TLS 1.1";
                case SslProtocols.Tls12:
                    return "TLS 1.2";
                case SslProtocols.Tls13:
                    return "TLS 1.3";
                default:
                    return "(unknown)";
            }
#pragma warning restore SYSLIB0039 // Type or member is obsolete
#pragma warning restore CS0618 // Type or member is obsolete
        }

    }
}
