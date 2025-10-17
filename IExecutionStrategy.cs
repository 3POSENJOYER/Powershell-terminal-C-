using System.Threading.Tasks;

public interface IExecutionStrategy
{
    Task<CommandResult> ExecuteAsync(string command);
    bool CanExecute(string command);
}