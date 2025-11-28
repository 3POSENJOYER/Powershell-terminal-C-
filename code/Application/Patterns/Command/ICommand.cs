using System.Threading.Tasks;

namespace PowerShellTerminal.Application.Patterns.Command
{
    public interface ICommand
    {
        Task ExecuteAsync();
    }
}
