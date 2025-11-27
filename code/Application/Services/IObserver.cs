using PowerShellTerminal.Domain.Models;

namespace PowerShellTerminal.Application.Services
{
    public interface IObserver
    {
        void Update(TerminalTheme theme);
    }
}
