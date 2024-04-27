using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace OAuch.Protocols.JWT {
    public abstract class JsonCollection : IEnumerable<string> {
        public JsonCollection(string json) {
            _originalJson = json;
            Root = JObject.Parse(json);
        }

        public bool ContainsKey(string key) {
            return Root[key] != null;
        }
        public T? ReadObject<T>(string key) where T : class {
            try {
                var token = Root[key];
                if (token == null)
                    return default;
                return token.ToObject<T>();
            } catch {
                return default;
            }
        }
        public T? ReadObject<T>(string parentKey, string key) where T : class {
            try {
                var parent = Root[parentKey];
                if (parent == null)
                    return default;
                var token = parent[key];
                if (token == null)
                    return default;
                return token.ToObject<T>();
            } catch {
                return default;
            }
        }

        public T? ReadValue<T>(string key) where T : struct {
            try {
                var token = Root[key];
                if (token == null)
                    return default(T);
                return token.ToObject<T>();
            } catch {
                return default(T);
            }
        }

        public IEnumerable<string> Keys => Root.Properties().Select(p => p.Name);

        protected internal JObject Root { get; }

        public int Count => Root.Count;

        public override string ToString() => ToString(true);
        public string ToString(bool base64Encoded, Formatting formatting = Formatting.None) {
            if (base64Encoded)
                return _originalJson;
            return Root.ToString(formatting);
        }

        IEnumerator IEnumerable.GetEnumerator() => this.GetEnumerator();
        public IEnumerator<string> GetEnumerator() {
            foreach (var node in Root) {
                yield return node.Key;
            }
        }

        private readonly string _originalJson;
    }
}
