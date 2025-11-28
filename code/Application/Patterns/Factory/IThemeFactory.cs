using PowerShellTerminal.Domain.Models;
using PowerShellTerminal.Application.Services;

namespace PowerShellTerminal.Application.Patterns.Factory
{
    public interface IThemeFactory
    {
        TerminalTheme CreateTheme();

        TerminalControl CreateTerminalControl(CommandInterpreter interpreter, HistoryService historyService);
    }
}
