using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace OAuch.Shared {
    public static class EncodingHelper {
        public static string Base64UrlEncode(byte[] input) => Base64UrlEncode(input, 0, input.Length);
        public static string Base64UrlEncode(byte[] input, int offset, int length) {
            if (input.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(input));

            var output = Convert.ToBase64String(input, offset, length);
            output = output.TrimEnd('='); // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }
        public static string Base64UrlEncode(string input) {
            return Base64UrlEncode(Encoding.UTF8.GetBytes(input));
        }
        public static byte[] Base64UrlDecode(string input) {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0:
                    break; // No pad chars in this case
                case 2:
                    output += "==";
                    break; // Two pad chars
                case 3:
                    output += "=";
                    break; // One pad char
                default:
                    throw new FormatException("Illegal base64url string.");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
        public static string Base64UrlDecodeAsString(string input) {
            return Encoding.UTF8.GetString(Base64UrlDecode(input));
        }
        public static string Base64Encode(byte[] input) {
            if (input.Length == 0)
                return "";

            return Convert.ToBase64String(input);
        }
        public static string Base64Encode(string input) {
            return Base64Encode(Encoding.UTF8.GetBytes(input));
        }
        public static byte[] Base64Decode(string input) {
            return Convert.FromBase64String(input); // Standard base64 decoder
        }
        public static string Base64DecodeAsString(string input) {
            return Encoding.UTF8.GetString(Base64Decode(input));
        }

        public static string UrlEncode(string input) {
            return HttpUtility.UrlEncode(input, Encoding.UTF8);
        }
        public static string UrlEncode(byte[] input) {
            return HttpUtility.UrlEncode(input);
        }
        public static string UrlDecode(string input) {
            return HttpUtility.UrlDecode(input, Encoding.UTF8);
        }
        public static byte[] FormUrlEncode(Dictionary<string, string?> collection) {
            return Encoding.UTF8.GetBytes(FormUrlEncodeAsString(collection));
        }
        public static string FormUrlEncodeAsString(Dictionary<string, string?> collection) {
            var sb = new StringBuilder();
            foreach (var key in collection.Keys) {
                if (key != null) {
                    var value = collection[key];
                    if (value != null) {
                        if (sb.Length > 0) {
                            sb.Append('&');
                        }
                        sb.Append(key);
                        sb.Append('=');
                        sb.Append(UrlEncode(value));
                    }
                }
            }
            return sb.ToString();
        }
        public static string FormUrlEncodeAsString(IFormCollection form) {
            var sb = new StringBuilder();
            foreach (var key in form.Keys) {
                if (key != null) {
                    var values = form[key];
                    for (int i = 0; i < values.Count; i++) {
                        if (sb.Length > 0) {
                            sb.Append('&');
                        }
                        sb.Append(UrlEncode(key));
                        sb.Append('=');
                        sb.Append(UrlEncode(values[i]));
                    }
                }
            }
            return sb.ToString();
        }
        public static Dictionary<string, string> EncodedFormToDictionary(string formData) {
            var dict = new Dictionary<string, string>();
            if (formData.Length > 0) {
                var parts = formData.Split('&');
                foreach (var part in parts) {
                    var components = part.Split('=');
                    if (components.Length == 2) {
                        dict.Add(UrlDecode(components[0]), UrlDecode(components[1]));
                    }
                }
            }
            return dict;
        }
        public static Dictionary<string, string> EncodedFormToDictionary(byte[] formData) {
            return EncodedFormToDictionary(Encoding.UTF8.GetString(formData));
        }
        public static string HtmlEncode(string input) {
            return HttpUtility.HtmlEncode(input);
        }

        public static Dictionary<string, string> ToDictionary(this NameValueCollection col) {
            var dict = new Dictionary<string, string>();
            foreach (var k in col.AllKeys) {
                if (k != null)
                    dict.Add(k, col[k]);
            }
            return dict;
        }

        public static Dictionary<string, string> JsonToDictionary(string json) {
            var dict = new Dictionary<string, string>();
            var o = JObject.Parse(json);
            if (o != null) {
                foreach (var kv in o) {
                    try {
                        string? val = kv.Value?.ToObject<string?>();
                        if (val != null)
                            dict[kv.Key] = val;
                    } catch { 
                        // couldn't convert to string; server uses some unsupported JSon structure
                    }
                }
            }
            return dict;
        }
    }
}
