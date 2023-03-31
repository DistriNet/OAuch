using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using Unity;
using Unity.Injection;
using Unity.Lifetime;

namespace OAuch.Shared {
    public class ServiceLocator {
        public static void Configure(IServiceProvider provider) {
            _provider = provider;
        }
        public static TProxyType? Resolve<TProxyType>() where TProxyType : class {
            return _provider?.GetService(typeof(TProxyType)) as TProxyType;
        }
        private static IServiceProvider? _provider;
    }
}