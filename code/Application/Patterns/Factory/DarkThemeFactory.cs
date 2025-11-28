using System.Drawing;
using PowerShellTerminal.Domain.Models;
using PowerShellTerminal.Application.Services;

namespace PowerShellTerminal.Application.Patterns.Factory
{
    public class DarkThemeFactory : IThemeFactory
    {
        public TerminalTheme CreateTheme()
        {
            return new TerminalTheme
            {
                BackgroundColor = Color.FromArgb(20,20,20),
                ForegroundColor = Color.FromArgb(230,230,230),
                ErrorColor = Color.OrangeRed,
                DefaultFont = new Font("Consolas", 12)
            };
        }

        public TerminalControl CreateTerminalControl(CommandInterpreter interpreter, HistoryService historyService)
        {
            var control = new DarkTerminalControl(interpreter, historyService);
            var theme = CreateTheme();
            control.SetBackgroundColor(theme.BackgroundColor);
            control.SetForegroundColor(theme.ForegroundColor);
            control.SetFont(theme.DefaultFont);
            return control;
        }
    }
}
