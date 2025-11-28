using System.Drawing;

namespace PowerShellTerminal.Domain.Patterns.Bridge
{
    public interface IRenderer
    {
        void RenderText(string text, Color color);
        void Clear();
    }
}
