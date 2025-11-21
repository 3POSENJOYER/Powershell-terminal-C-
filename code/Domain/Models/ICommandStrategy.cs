using System.Threading.Tasks;

namespace PowerShellTerminal.Domain.Models
{
    public interface ICommandStrategy
    {
        Task<CommandResult> ExecuteAsync(string command);
    }
}
