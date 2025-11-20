namespace PowerShellTerminal.Domain.Entities
{
    public class UserSettings
    {
        public int Id { get; set; }
        public string UserName { get; set; } = Environment.UserName;
        public string ThemeName { get; set; } = "Default";
        public string FontFamily { get; set; } = "Consolas";
        public int FontSize { get; set; } = 12;
        public string BackgroundColor { get; set; } = "Black";
        public string ForegroundColor { get; set; } = "White";
        public int WindowWidth { get; set; } = 800;
        public int WindowHeight { get; set; } = 600;
        public DateTime LastModified { get; set; } = DateTime.Now;
    }
}