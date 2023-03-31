using Newtonsoft.Json;
using OAuch.Shared.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuch.Helpers {
    public static class OAuchJsonConvert {
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
