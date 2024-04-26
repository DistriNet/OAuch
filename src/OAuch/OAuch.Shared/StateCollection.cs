using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared {
    public class StateCollection {
        public StateCollection() {
            _bag = [];
        }
        /// <summary>
        /// Searches the state collection for the given key. 
        /// </summary>
        /// <typeparam name="T">Specifies the type of the object that is retrieved from the state collection.</typeparam>
        /// <param name="key">The key to look up in the state collection.</param>
        /// <returns>If the key is found, it returns the saved value of type T, null otherwise.</returns>
        public T? Find<T>(StateKeys key) where T : class {
            T? ret = null;
            if (_bag.TryGetValue(key, out object? value)) {
                ret = value as T;
            }
            return ret;
        }
        /// <summary>
        /// Retrieves a value from the state collection.
        /// </summary>
        /// <typeparam name="T">Specifies the type of the object that is retrieved from the state collection.</typeparam>
        /// <param name="key">The key to look up in the state collection.</param>
        /// <returns>If the key is found, it returns the saved value of type T. If the key is not found, a new instance of type T is created and returned, and this instance is also added to the state collection.</returns>
        public T Get<T>(StateKeys key) where T : class, new() {
            var ret = Find<T>(key);
            if (ret == null) {
                ret = new T();
                Add(key, ret);
            }
            return ret;
        }
        /// <summary>
        /// Adds a value to the state collection.
        /// </summary>
        /// <typeparam name="T">Specifies the type of the object that is stored in the state collection.</typeparam>
        /// <param name="key">The key that is used to save the object in the state collection.</param>
        /// <param name="value">The object to save.</param>
        public void Add<T>(StateKeys key, T value) where T : class {
            _bag[key] = value;
        }

        [JsonProperty]
        private readonly Dictionary<StateKeys, object> _bag;
    }
    public enum StateKeys {
        ModernConnectionResults,
        SecurityReports,
        UrlMappings,
        TokenCache,
        FeatureCache,
        WorkingPkceTypes,
        JsonWebKeySet
    }
}
