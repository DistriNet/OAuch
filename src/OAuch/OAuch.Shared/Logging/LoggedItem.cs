using System;

namespace OAuch.Shared.Logging {
    public abstract class LoggedItem {
        public LoggedItem() : this(DateTime.Now) { }
        public LoggedItem(DateTime createdAt) {
            this.CreatedAt = createdAt;
        }

        public virtual DateTime CreatedAt { get; set; }
        public abstract void Accept(ILogVisitor formatter);
    }
}