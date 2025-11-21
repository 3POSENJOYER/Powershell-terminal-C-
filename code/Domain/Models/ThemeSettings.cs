using PowerShellTerminal.Domain.Prototype;

namespace PowerShellTerminal.Domain.Models
{
    public class ThemeSettings : IPrototype
    {
        public string BackgroundColor { get; set; }
        public string TextColor { get; set; }
        public int FontSize { get; set; }

        public IPrototype Clone()
        {
            return new ThemeSettings
            {
                BackgroundColor = this.BackgroundColor,
                TextColor = this.TextColor,
                FontSize = this.FontSize
            };
        }
    }
}
