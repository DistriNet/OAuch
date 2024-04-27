﻿using System.Collections.Generic;

namespace OAuch.Compliance.Tests.Concurrency {
    public class ConcurrencyInfo {
        public int TotalRequestCount { get; set; }
        public int SucceededRequestCount { get; set; }
        public List<string>? ReturnedAccessTokens { get; set; }
        public List<string>? ReturnedRefreshTokens { get; set; }
        public List<string>? WorkingAccessTokens { get; set; }
        public List<string>? WorkingRefreshTokens { get; set; }
        public int AccessTokensValidCount { get; set; }
        public int RefreshTokensValidCount { get; set; }
    }
}
