using Newtonsoft.Json;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.Helpers {
    public static class OAuchJsonConvert {
        // TODO: add new ISerializationBuilder to catch serialization errors (because test cases are renamed or removed)
        // https://stackoverflow.com/questions/60972554/getting-error-resolving-type-specified-in-json
        public static T Deserialize<T>(string json) {
            return JsonConvert.DeserializeObject<T>(json, new JsonSerializerSettings { 
                TypeNameHandling = TypeNameHandling.Auto
            });
        }

        public static string Serialize(object o, Formatting formatting = Formatting.None) {
            return JsonConvert.SerializeObject(o, formatting, new JsonSerializerSettings { 
                 TypeNameHandling = TypeNameHandling.Auto
            });
        }
    }
}
