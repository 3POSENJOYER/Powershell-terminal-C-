using PowerShellTerminal.Domain.Prototype;

namespace PowerShellTerminal.Domain.Models
{
    public class ThemeSettings : IPrototype
    {
        public string BackgroundColor { get; set; }
        public string TextColor { get; set; }
        public int FontSize { get; set; }

        public ThemeSettings CloneSettings()
        {
            return new ThemeSettings
            {
                BackgroundColor = BackgroundColor,
                TextColor = TextColor,
                FontSize = FontSize
            };
        }

        public IPrototype Clone()
        {
            return CloneSettings();
        }
    }
}
