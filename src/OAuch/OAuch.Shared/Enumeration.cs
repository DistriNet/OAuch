using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace OAuch.Shared {
    public abstract class Enumeration : IComparable {
        public string Name { get; private set; }

        public int Id { get; private set; }

        protected Enumeration(int id, string name) {
            Id = id;
            Name = name;
        }

        public override string ToString() => Name;

        public static IEnumerable<T> GetAll<T>() where T : Enumeration {
            var fields = typeof(T).GetFields(BindingFlags.Public |
                                             BindingFlags.Static |
                                             BindingFlags.DeclaredOnly);

            return fields.Select(f => f.GetValue(null)).Cast<T>().OrderBy(c => c.Id);
        }

        public override bool Equals(object? obj) {
            if (obj is not Enumeration otherValue)
                return false;

            var typeMatches = GetType().Equals(otherValue.GetType());
            var valueMatches = Id.Equals(otherValue.Id);

            return typeMatches && valueMatches;
        }

        public override int GetHashCode() {
            return Id.GetHashCode();
        }

        public int CompareTo(object? other) {
            if (other is not Enumeration oc)
                return Id.CompareTo(null);
            return Id.CompareTo(oc.Id);
        }

        // Other utility methods ...
    }
}
