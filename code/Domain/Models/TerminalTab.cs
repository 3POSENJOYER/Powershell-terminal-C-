using PowerShellTerminal.Application.Services;
using System.Windows.Forms;

namespace PowerShellTerminal.Domain.Models
{
    public class TerminalTab
    {
        public TerminalControl TerminalControl { get; set; }
        public CommandInterpreter Interpreter { get; set; }
        public TabPage TabPage { get; set; }

        public TerminalTab(ThemeManager themeManager, HistoryService historyService)
        {
            Interpreter = new CommandInterpreter();
            TerminalControl = new TerminalControl(Interpreter, historyService);
            TabPage = new TabPage("PowerShell");
            
            
            TerminalControl.AsControl().Dock = DockStyle.Fill;
            TabPage.Controls.Add(TerminalControl.AsControl());
            
        
            TabPage.Enter += (s, e) => TerminalControl.FocusInput();
        }

        public void ApplyTheme(TerminalTheme theme)
        {
            TerminalControl.SetBackgroundColor(theme.BackgroundColor);
            TerminalControl.SetForegroundColor(theme.ForegroundColor);
            TerminalControl.SetFont(theme.DefaultFont);
        }

        public void SetFocus()
        {
            TerminalControl.FocusInput();
        }
    }
}