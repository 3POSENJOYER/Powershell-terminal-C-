namespace PowerShellTerminal.Domain.Models
{
    public class TerminalExpression : Expression
    {
        public string CommandText { get; set; }

        public TerminalExpression(string commandText)
        {
            CommandText = commandText;
        }

        public override void Interpret(CommandContext ctx)
        {
            ctx.SetOutput($"Executing: {CommandText}");
        }
    }
}
