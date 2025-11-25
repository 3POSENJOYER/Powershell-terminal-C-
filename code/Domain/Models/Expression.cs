namespace PowerShellTerminal.Domain.Models
{
    public abstract class Expression
    {
        public abstract void Interpret(CommandContext ctx);
    }
}
