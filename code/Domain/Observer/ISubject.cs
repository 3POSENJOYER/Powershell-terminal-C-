namespace PowerShellTerminal.Domain.Observer
{
    /// <summary>
    /// Subject interface for notifying observers of state changes.
    /// </summary>
    public interface ISubject
    {
        /// <summary>Register an observer to receive notifications.</summary>
        void Attach(IObserver observer);
        
        /// <summary>Unregister an observer from receiving notifications.</summary>
        void Detach(IObserver observer);
        
        /// <summary>Notify all attached observers of a state change.</summary>
        void Notify();
    }
}
