namespace OAuch.Shared {
    public abstract class StateKey { }
    /// <summary>
    /// The class that can be used as a key for a state collection.
    /// </summary>
    /// <typeparam name="T">Specifies the type of the object that is stored in and retrieved from the state collection.</typeparam>
    public class StateKey<T> : StateKey { }
}
