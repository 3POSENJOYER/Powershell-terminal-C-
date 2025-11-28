using PowerShellTerminal.Application.Services;
using System.Windows.Forms;
using PowerShellTerminal.Domain.Patterns.Bridge;

namespace PowerShellTerminal.Domain.Models
{
    public class TerminalTab
    {
        public string Title { get; set; }
        public TerminalTheme Theme { get; set; }
        public PowerShellSession Session { get; set; }
        public TerminalControl TerminalControl { get; set; }
        public PowerShellTerminal.Domain.Patterns.Bridge.TerminalAbstraction TerminalRenderer { get; set; }
        public CommandInterpreter Interpreter { get; set; }
        public TabPage TabPage { get; set; }
        private ThemeManager _themeManager;

        public TerminalTab(TerminalControl terminalControl, ThemeManager themeManager, HistoryService historyService)
        {
            Title = "PowerShell";
            Theme = new TerminalTheme();
            Session = new PowerShellSession();
            Interpreter = null; 
            TerminalControl = terminalControl;
            TabPage = new TabPage(Title);
            _themeManager = themeManager;

            TerminalControl.AsControl().Dock = DockStyle.Fill;
            TabPage.Controls.Add(TerminalControl.AsControl());

            TabPage.Enter += (s, e) => TerminalControl.FocusInput();

            var guiRenderer = new GuiRenderer(TerminalControl);
            TerminalRenderer = new TerminalAbstraction(guiRenderer);
        }

        public void ApplyTheme(TerminalTheme theme)
        {
            Theme = theme;
            TerminalControl.SetBackgroundColor(theme.BackgroundColor);
            TerminalControl.SetForegroundColor(theme.ForegroundColor);
            TerminalControl.SetFont(theme.DefaultFont);
        }

        public void SetFocus()
        {
            TerminalControl.FocusInput();
        }

        public TerminalTab CloneTab()
        {
            var newInterpreter = new CommandInterpreter();
            var newHistory = new HistoryService();
            var newControl = _themeManager.CreateTerminalControl(newInterpreter, newHistory);

            var cloned = new TerminalTab(newControl, _themeManager, newHistory)
            {
                Title = this.Title,
                Theme = this.Theme?.Clone(),
                Session = new PowerShellSession()
            };
            var gui = new GuiRenderer(cloned.TerminalControl);
            cloned.TerminalRenderer = new TerminalAbstraction(gui);
            return cloned;
        }
    }
}