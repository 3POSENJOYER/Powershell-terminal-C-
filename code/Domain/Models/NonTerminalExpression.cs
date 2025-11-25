namespace PowerShellTerminal.Domain.Models
{
    public class NonTerminalExpression : Expression
    {
        public List<Expression> Children { get; set; } = new();

        public void AddChild(Expression expression)
        {
            Children.Add(expression);
        }

        public override void Interpret(CommandContext ctx)
        {
            foreach (var child in Children)
            {
                child.Interpret(ctx);
            }
        }
    }
}
