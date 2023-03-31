using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OAuch.Shared;
using OAuch.Shared.Logging;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace OAuch.Protocols.JWK {
   public class JwkSet : ICollection<JsonWebKey> {
        [JsonConstructor]
        private JwkSet() {
            this.Keys = new List<JsonWebKey>();
        }
        private JwkSet(List<JsonWebKey> keys) {
            this.Keys = keys;
        }

        public JsonWebKey? this[string id] {
            get {
                return Keys.FirstOrDefault(c => c.Id == id);
            }
        }
        public int Count => Keys.Count;
        public IEnumerator<JsonWebKey> GetEnumerator() => Keys.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => Keys.GetEnumerator();

        [JsonIgnore]
        private List<JsonWebKey> Keys { get; set; }

        public bool IsReadOnly => false;
        public void Add(JsonWebKey item) => Keys.Add(item);
        public void Clear() => Keys.Clear();
        public bool Contains(JsonWebKey item) => Keys.Contains(item);
        public void CopyTo(JsonWebKey[] array, int arrayIndex) => Keys.CopyTo(array, arrayIndex);
        public bool Remove(JsonWebKey item) => Keys.Remove(item);

        public override string ToString() {
            return ToString(Formatting.None);
        }
        public string ToString(Formatting formatting) {
            return JsonConvert.SerializeObject(new { 
                keys = Keys
            }, formatting);
        }

        public static JwkSet? Create(string json, LogContext logger) {
            try {
                var set = JObject.Parse(json);
                var keys = set["keys"] as JArray;
                if (keys == null)
                    return null;
                var keyList = new List<JsonWebKey>();
                foreach (var jo in keys) {
                    var key = JsonWebKey.Create(jo);
                    if (key != null)
                        keyList.Add(key);
                }
                var ks = new JwkSet(keyList);
                logger.Log(ks);
                return ks;
            } catch { }
            return null;
        }
    }
}
