using System.Threading.Tasks;
using PowerShellTerminal.Application.Patterns.Command;
using PowerShellTerminal.Application.Services;

namespace PowerShellTerminal.Application.Patterns.Command
{
    public class ApplyDarkThemeCommand : ICommand
    {
        private readonly ThemeManager _themeManager;

        public ApplyDarkThemeCommand(ThemeManager themeManager)
        {
            _themeManager = themeManager;
        }

        public Task ExecuteAsync()
        {
            _themeManager.ApplyDarkTheme();
            return Task.CompletedTask;
        }
    }
}
