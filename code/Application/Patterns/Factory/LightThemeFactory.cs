using System.Drawing;
using PowerShellTerminal.Domain.Models;
using PowerShellTerminal.Application.Services;

namespace PowerShellTerminal.Application.Patterns.Factory
{
    public class LightThemeFactory : IThemeFactory
    {
        public TerminalTheme CreateTheme()
        {
            return new TerminalTheme
            {
                BackgroundColor = Color.White,
                ForegroundColor = Color.Black,
                ErrorColor = Color.Red,
                DefaultFont = new Font("Consolas", 12)
            };
        }

        public TerminalControl CreateTerminalControl(CommandInterpreter interpreter, HistoryService historyService)
        {
            var control = new LightTerminalControl(interpreter, historyService);
            var theme = CreateTheme();
            control.SetBackgroundColor(theme.BackgroundColor);
            control.SetForegroundColor(theme.ForegroundColor);
            control.SetFont(theme.DefaultFont);
            return control;
        }
    }
}
