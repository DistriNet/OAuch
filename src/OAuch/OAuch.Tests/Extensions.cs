using OAuch.Compliance.Tests;
using OAuch.Shared.Enumerations;
using System;
using System.Security.Authentication;

namespace OAuch.Compliance {
    public static class Extensions {
        public static string Format(this TestOutcomes outcome, TestResultFormatter formatter) {
            return outcome switch {
                TestOutcomes.SpecificationFullyImplemented => formatter.CountermeasureFullyImplemented,
                TestOutcomes.SpecificationNotImplemented => formatter.CountermeasureNotImplemented,
                TestOutcomes.SpecificationPartiallyImplemented => formatter.CountermeasurePartiallyImplemented,
                TestOutcomes.Failed => formatter.Failed,
                TestOutcomes.Skipped => formatter.Skipped,
                _ => throw new NotSupportedException(),
            };
        }
        public static string ToName(this SslProtocols p) {
#pragma warning disable CS0618 // Type or member is obsolete
#pragma warning disable SYSLIB0039 // Type or member is obsolete
            return p switch {
                SslProtocols.Ssl2 => "SSL 2.0",
                SslProtocols.Ssl3 => "SSL 3.0",
                SslProtocols.Tls => "TLS 1.0",
                SslProtocols.Tls11 => "TLS 1.1",
                SslProtocols.Tls12 => "TLS 1.2",
                SslProtocols.Tls13 => "TLS 1.3",
                _ => "(unknown)"
            };
#pragma warning restore SYSLIB0039 // Type or member is obsolete
#pragma warning restore CS0618 // Type or member is obsolete
        }

    }
}
