using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

public class PowerShellInterpreter : ICommandInterpreter
{
    private readonly List<IExecutionStrategy> _strategies;
    
    public PowerShellInterpreter()
    {
        _strategies = new List<IExecutionStrategy>
        {
            new PowerShellExecutionStrategy(),
            new ExecutableExecutionStrategy()
        };
    }
    
    public async Task<CommandResult> InterpretAsync(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return CommandResult.Empty;
            
        foreach (var strategy in _strategies)
        {
            if (strategy.CanExecute(input))
            {
                return await strategy.ExecuteAsync(input);
            }
        }
        
        return new CommandResult { Errors = $"Cannot execute: {input}", Success = false };
    }
    
    public bool Validate(string input) => !string.IsNullOrWhiteSpace(input);
    
    public string GetSuggestion(string partialInput) => string.Empty;
}

public interface ICommandInterpreter
{
    Task<CommandResult> InterpretAsync(string input);
    bool Validate(string input);
    string GetSuggestion(string partialInput);
}