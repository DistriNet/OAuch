using Newtonsoft.Json.Linq;
using OAuch.Protocols.JWK;
using OAuch.Protocols.JWT;
using OAuch.Shared;
using OAuch.Shared.Enumerations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace OAuch.Compliance.Tests.Shared {
    public static class Extensions {
        public static JsonWebKey? GetAsymmetricSigningKey(this JoseHeader header, JwkSet keyset, Action<string> log) {
            var kid = header.KeyId;
            JsonWebKey? key;
            if (kid == null) {
                // 'kid' is required if there are multiple keys in the key set
                if (keyset.Count == 1) {
                    key = keyset.First();
                } else {
                    log("The ID token does not have a key identifier ('kid') claim in its header.");
                    return null;
                }
            } else {
                key = keyset[kid];
                if (key == null) {
                    log($"The key with identifier '{kid}' could not be found in the key set downloaded from the JWKS URI.");
                    return null;
                }
            }
            if (key.Algorithm != null && key.Algorithm != header.Algorithm) {
                log($"The key from the JWKS key store only allows for a specific algorithm to be used, but the ID token uses another algorithm. (expected '{key.Algorithm.Name}', received '{header.Algorithm!.Name}')");
                return null;
            }
            if (key.Usage != null && key.Usage != JwkKeyUsage.Sign) {
                log($"The key from the JWKS key store does not allow it to be used for signing.");
                return null;
            }
            return key;
        }

        public static PKCESupportTypes MostSecureSupportedPKCEType(this TestRunContext context) {
            var supportedTypes = context.State.Get<List<PKCESupportTypes>>(StateKeys.WorkingPkceTypes);
            if (supportedTypes.Contains(PKCESupportTypes.Hash))
                return PKCESupportTypes.Hash;
            if (supportedTypes.Contains(PKCESupportTypes.Plain))
                return PKCESupportTypes.Plain;
            return PKCESupportTypes.None;
        }
        public static string DuplicateParameter(this string formUrlEncoded) {
            string query = formUrlEncoded;
            if (Uri.TryCreate(formUrlEncoded, UriKind.Absolute, out var result)) {
                // the input is a full url
                query = result.Query;
            }

            var components = HttpUtility.ParseQueryString(query);
            var grantType = components.Get("grant_type");
            var responseType = components.Get("response_type");
            var clientId = components.Get("client_id");
            if (grantType != null) {
                return formUrlEncoded + "&grant_type=" + grantType;
            } else if (responseType != null) {
                return formUrlEncoded + "&response_type=" + responseType;
            } else if (clientId != null) {
                return formUrlEncoded + "&client_id=" + clientId;
            } else { // no grant_type parameter; duplicate the last one instead
                int idx = formUrlEncoded.LastIndexOf('&');
                if (idx == -1)
                    return formUrlEncoded; // no parameters
                return formUrlEncoded + "&" + formUrlEncoded.Substring(idx + 1);
            }
        }
        public static byte[] DuplicateParameter(this byte[] utf8FormUrlEncoded) {
            return Encoding.UTF8.GetBytes(DuplicateParameter(Encoding.UTF8.GetString(utf8FormUrlEncoded)));
        }
        /// <summary>
        /// returns bits of entropy represented in a given string, per 
        /// http://en.wikipedia.org/wiki/Entropy_(information_theory) 
        /// </summary>
        public static double CalculateEntropy(this string s) {
            var map = new Dictionary<char, int>();
            foreach (char c in s) {
                if (!map.ContainsKey(c))
                    map.Add(c, 1);
                else
                    map[c] += 1;
            }

            double result = 0.0;
            int len = s.Length;
            foreach (var item in map) {
                var frequency = (double)item.Value / len;
                result -= frequency * (Math.Log(frequency) / Math.Log(2));
            }

            return result;
        }
        public static double StdDev(this IEnumerable<double> values) {
            double ret = 0;
            int count = values.Count();
            if (count > 1) {
                //Compute the Average
                double avg = values.Average();

                //Perform the Sum of (value-avg)^2
                double sum = values.Sum(d => (d - avg) * (d - avg));

                //Put it all together
                ret = Math.Sqrt(sum / count);
            }
            return ret;
        }
        public static double Median(this IEnumerable<double> sourceNumbers) {
            //make sure the list is sorted, but use a new array
            double[] sortedPNumbers = sourceNumbers.ToArray();
            if (sortedPNumbers.Length == 0)
                return 0;
            Array.Sort(sortedPNumbers);

            //get the median
            int size = sortedPNumbers.Length;
            int mid = size / 2;
            double median = (size % 2 != 0) ? (double)sortedPNumbers[mid] : ((double)sortedPNumbers[mid] + (double)sortedPNumbers[mid - 1]) / 2;
            return median;
        }
        public static (double Average, double StdDev) GetStatistics(this List<double> values) {
            double avg = 0, stddev = 0;
            int count = values.Count;
            if (count > 1) {
                //Compute the Average
                avg = values.Average();

                //Perform the Sum of (value-avg)^2
                double sum = values.Sum(d => (d - avg) * (d - avg));

                //Put it all together
                stddev = Math.Sqrt(sum / count);
            }
            return (avg, stddev);
        }
    }
}
