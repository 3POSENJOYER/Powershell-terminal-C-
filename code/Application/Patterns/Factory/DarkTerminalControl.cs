using System.Drawing;
using PowerShellTerminal.Application.Services;
using PowerShellTerminal.Domain.Models;

namespace PowerShellTerminal.Application.Patterns.Factory
{
    public class DarkTerminalControl : TerminalControl
    {
        public DarkTerminalControl(CommandInterpreter interpreter, HistoryService historyService)
            : base(interpreter, historyService)
        {
            SetBackgroundColor(Color.FromArgb(20,20,20));
            SetForegroundColor(Color.FromArgb(230,230,230));
            SetFont(new Font("Consolas", 12));
        }
    }
}
