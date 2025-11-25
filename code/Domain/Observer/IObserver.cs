namespace PowerShellTerminal.Domain.Observer
{
    /// <summary>
    /// Observer interface for receiving notifications when state changes occur.
    /// </summary>
    public interface IObserver
    {
        /// <summary>Attach this observer to a subject.</summary>
        void Attach(IObserver observer);
        
        /// <summary>Detach this observer from a subject.</summary>
        void Detach(IObserver observer);
        
        /// <summary>Called when the observed subject's state changes.</summary>
        void Notify();
    }
}
