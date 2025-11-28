using System.Threading.Tasks;
using PowerShellTerminal.Application.Patterns.Command;
using PowerShellTerminal.Application.Services;

namespace PowerShellTerminal.Application.Patterns.Command
{
    public class ApplyLightThemeCommand : ICommand
    {
        private readonly ThemeManager _themeManager;

        public ApplyLightThemeCommand(ThemeManager themeManager)
        {
            _themeManager = themeManager;
        }

        public Task ExecuteAsync()
        {
            _themeManager.ApplyLightTheme();
            return Task.CompletedTask;
        }
    }
}
