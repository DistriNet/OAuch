using OAuch.Compliance;

namespace OAuch.Helpers {
    public class HelperMethods {
        public static string ShortenTestId(string? id, bool trimEnd = false) {
            if (id == null)
                return "?";
            string test = id;
            if (id.StartsWith("OAuch.Compliance.Tests."))
                test = id[23..];
            if (trimEnd && test.EndsWith("Test"))
                test = test[..^4];
            return test;
        }
        public static string LengthenTestId(string id) {
            if (!id.StartsWith("OAuch.Compliance.Tests."))
                id = "OAuch.Compliance.Tests." + id;
            if (!id.EndsWith("Test")) {
                if (!ComplianceDatabase.Tests.ContainsKey(id))
                    id += "Test";
            }
            return id;
        }
        public static string GetTestCategory(string shortId) {
            int index = shortId.IndexOf('.');
            if (index == -1)
                return "";
            else
                return shortId[..index];
        }
    }
}
