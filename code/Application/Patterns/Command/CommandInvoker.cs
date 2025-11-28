using System.Threading.Tasks;
using PowerShellTerminal.Application.Patterns.Command;

namespace PowerShellTerminal.Application.Patterns.Command
{
    public class CommandInvoker
    {
        public async Task InvokeAsync(ICommand command)
        {
            if (command == null) return;
            await command.ExecuteAsync();
        }
    }
}
