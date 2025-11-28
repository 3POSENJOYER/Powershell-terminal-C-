using System.Threading.Tasks;
using PowerShellTerminal.Application.Patterns.Command;
using PowerShellTerminal.Application.Services;

namespace PowerShellTerminal.Application.Patterns.Command
{
    public class OpenNewTabCommand : ICommand
    {
        private readonly TabManager _tabManager;

        public OpenNewTabCommand(TabManager tabManager)
        {
            _tabManager = tabManager;
        }

        public Task ExecuteAsync()
        {
            _tabManager.CreateNewTab();
            return Task.CompletedTask;
        }
    }
}
