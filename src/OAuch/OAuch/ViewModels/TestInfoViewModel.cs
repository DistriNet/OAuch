using OAuch.Compliance;
using OAuch.Helpers;
using System.Collections.Generic;
using System.Linq;

namespace OAuch.ViewModels {
    public class TestInfoViewModel {
        private static readonly Dictionary<string, string> CategoryDescriptions = new() {
            ["DocumentSupport"] = "Document Support",
            ["Features"] = "Feature Support",
            ["AuthEndpoint"] = "Authorization Endpoint",
            ["TokenEndpoint"] = "Token Endpoint",
            ["DeviceAuthEndpoint"] = "Device Authorization Endpoint",
            ["ApiEndpoint"] = "API Endpoint",
            ["Tokens"] = "Access and Refresh Tokens",
            ["IdTokens"] = "Identity Tokens",
            ["Jwt"] = "JWTs",
            ["Pkce"] = "PKCE",
            ["Revocation"] = "Revocation"
        };

        public TestInfoViewModel(Test test) {
            this.Test = test;
            this.ShortId = HelperMethods.ShortenTestId(test.TestId, true);
            this.Category = HelperMethods.GetTestCategory(this.ShortId);
        }
        public string ShortId { get; set; }
        public string TestName => ShortId[(Category.Length + 1)..];
        public string Category { get; set; }
        public string CategoryDescription {
            get {
                if (CategoryDescriptions.TryGetValue(this.Category, out var desc)) {
                    return desc;
                }
                return this.Category;
            }
        }
        public Test Test { get; set; }

        public static IComparer<string> TestCategoryComparer {
            get {
                return new CategoryComparer();
            }
        }

        private class CategoryComparer : IComparer<string> {
            public CategoryComparer() {
                _values = [.. TestInfoViewModel.CategoryDescriptions.Values];
                _notFound = [];
            }
            public int Compare(string? x, string? y) {
                if (x is null && y is null)
                    return 0;
                if (x is null)
                    return -1;
                if (y is null)
                    return 1;
                var xi = GetIndex(x);
                var yi = GetIndex(y);
                if (xi == yi)
                    return 0;
                if (xi < yi)
                    return -1;
                return 1;
            }
            private int GetIndex(string cat) {
                int index = _values.IndexOf(cat);
                if (index >= 0)
                    return index;
                index = _notFound.IndexOf(cat);
                if (index >= 0)
                    return index;
                _notFound.Add(cat);
                return _values.Count + _notFound.Count - 1;
            }
            private readonly List<string> _values;
            private readonly List<string> _notFound;
        }
    }
}
