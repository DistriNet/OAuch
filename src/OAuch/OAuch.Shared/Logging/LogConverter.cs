using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuch.Shared.Logging {
    public interface ILogConverter<TFrom> {
        public abstract LoggedItem Convert(TFrom item);
    }
}