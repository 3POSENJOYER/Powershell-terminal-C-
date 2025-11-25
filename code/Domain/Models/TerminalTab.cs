using PowerShellTerminal.Application.Services;
using PowerShellTerminal.Domain.Prototype;
using PowerShellTerminal.Domain.Observer;
using System.Windows.Forms;

namespace PowerShellTerminal.Domain.Models
{
    public class TerminalTab : IPrototype, IObserver
    {
        public string Title { get; set; }
        public TerminalTheme Theme { get; set; }
        public PowerShellSession Session { get; set; }
        public TerminalControl TerminalControl { get; set; }
        public CommandInterpreter Interpreter { get; set; }
        public TabPage TabPage { get; set; }
        private ThemeManager _themeManager;

        public TerminalTab(ThemeManager themeManager, HistoryService historyService)
        {
            Title = "PowerShell";
            Theme = new TerminalTheme();
            Session = new PowerShellSession();
            Interpreter = new CommandInterpreter();
            TerminalControl = new TerminalControl(Interpreter, historyService);
            TabPage = new TabPage(Title);
            _themeManager = themeManager;
            
            TerminalControl.AsControl().Dock = DockStyle.Fill;
            TabPage.Controls.Add(TerminalControl.AsControl());
            
            TabPage.Enter += (s, e) => TerminalControl.FocusInput();
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

        public void Notify()
        {
            ApplyTheme(_themeManager.GetCurrentTheme());
        }

        public void Attach(IObserver observer)
        {
            
        }

        public void Detach(IObserver observer)
        {
            // Implementation for detaching observer
        }

        public IPrototype Clone()
        {
            var clonedTab = new TerminalTab(new ThemeManager(), new HistoryService())
            {
                Title = this.Title,
                Theme = (TerminalTheme)this.Theme?.Clone(),
                Session = (PowerShellSession)this.Session?.Clone()
            };
            return clonedTab;
        }
    }
}