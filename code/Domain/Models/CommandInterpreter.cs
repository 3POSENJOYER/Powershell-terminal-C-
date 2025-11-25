using System.Threading.Tasks;

namespace PowerShellTerminal.Domain.Models
{
    public class CommandInterpreter
    {
        private ICommandStrategy _strategy;

        public CommandInterpreter()
        {
            _strategy = new PowerShellCommandStrategy();
        }

        public void SetStrategy(ICommandStrategy strategy)
        {
            _strategy = strategy;
        }

        public Expression Parse(string input)
        {
            var parts = input.Split(';', System.StringSplitOptions.RemoveEmptyEntries);
            
            if (parts.Length == 1)
            {
                return new TerminalExpression(input.Trim());
            }

            var nonTerminal = new NonTerminalExpression();
            foreach (var part in parts)
            {
                nonTerminal.AddChild(new TerminalExpression(part.Trim()));
            }
            return nonTerminal;
        }

        public void Execute(string input)
        {
            var expression = Parse(input);
            var context = new CommandContext();
            expression.Interpret(context);
        }

        public async Task<CommandResult> ExecuteCommand(string command)
        {
            return await _strategy.ExecuteAsync(command);
        }
    }
}