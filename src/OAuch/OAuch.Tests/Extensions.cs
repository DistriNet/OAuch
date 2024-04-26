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
            return p switch {
                SslProtocols.Ssl2 => "SSL 2.0",
                SslProtocols.Ssl3 => "SSL 3.0",
                SslProtocols.Tls => "TLS 1.0",
                SslProtocols.Tls11 => "TLS 1.1",
                SslProtocols.Tls12 => "TLS 1.2",
                SslProtocols.Tls13 => "TLS 1.3",
                _ => "(unknown)",
            };
        }

    }
}
