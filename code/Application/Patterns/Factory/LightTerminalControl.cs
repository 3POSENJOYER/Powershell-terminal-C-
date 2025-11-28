using System.Drawing;
using PowerShellTerminal.Application.Services;
using PowerShellTerminal.Domain.Models;

namespace PowerShellTerminal.Application.Patterns.Factory
{
    public class LightTerminalControl : TerminalControl
    {
        public LightTerminalControl(CommandInterpreter interpreter, HistoryService historyService)
            : base(interpreter, historyService)
        {
            SetBackgroundColor(Color.White);
            SetForegroundColor(Color.Black);
            SetFont(new Font("Consolas", 12));
        }
    }
}
