namespace PowerShellTerminal.Domain.Observer
{
    public interface IObserver
    {
        void Attach(IObserver observer);
        void Detach(IObserver observer);
        void Notify();
    }
}
