using System.Threading.Tasks;
using PowerShellTerminal.Application.Patterns.Command;
using PowerShellTerminal.Application.Services;

namespace PowerShellTerminal.Application.Patterns.Command
{
    public class CloseTabCommand : ICommand
    {
        private readonly TabManager _tabManager;

        public CloseTabCommand(TabManager tabManager)
        {
            _tabManager = tabManager;
        }

        public Task ExecuteAsync()
        {
            _tabManager.CloseCurrentTab();
            return Task.CompletedTask;
        }
    }
}
