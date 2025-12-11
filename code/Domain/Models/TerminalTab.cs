using PowerShellTerminal.Application.Services;
using System.Windows.Forms;

namespace PowerShellTerminal.Domain.Models
{
    public class TerminalTab : IObserver
    {
        public TerminalControl TerminalControl { get; set; }
        public CommandInterpreter Interpreter { get; set; }
        public TabPage TabPage { get; set; }
    
        private readonly ThemeManager _themeManager;

        public TerminalTab(ThemeManager themeManager, HistoryService historyService, int sessionId)
        {
            Interpreter = new CommandInterpreter();
            TerminalControl = new TerminalControl(Interpreter, historyService, sessionId);
            TabPage = new TabPage("PowerShell");
                                                        
            TerminalControl.AsControl().Dock = DockStyle.Fill;
            TabPage.Controls.Add(TerminalControl.AsControl());

            TabPage.Enter += (s, e) => TerminalControl.FocusInput();
            _themeManager = themeManager;
            _themeManager?.Attach(this);
        }

        public void ApplyTheme(TerminalTheme theme)
        {
            TerminalControl.SetBackgroundColor(theme.BackgroundColor);
            TerminalControl.SetForegroundColor(theme.ForegroundColor);
            TerminalControl.SetFont(theme.DefaultFont);
        }

        public void Update(TerminalTheme theme)
        {
            if (theme != null)
            {
                ApplyTheme(theme);
            }
        }

        public void SetFocus()
        {
            TerminalControl.FocusInput();
        }
    }
}