using System.Collections.Generic;

namespace PowerShellTerminal.Domain.Models
{
    public class NonTerminalExpression : Expression
    {
        public List<Expression> Children { get; } = new List<Expression>();

        public void AddChild(Expression expression)
        {
            if (expression == null) return;
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
