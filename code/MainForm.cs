using PowerShellTerminal.Application.Services;
using WinFormsApp = System.Windows.Forms.Application;
using System.Windows.Forms;

namespace PowerShellTerminal
{
    public partial class MainForm : Form
    {
        private TabManager _tabManager;
        private ThemeManager _themeManager;
        private HistoryService _historyService;
        private TabControl _mainTabControl;

        public MainForm()
        {
            InitializeComponent();
            InitializeApplication();
        }

        private void InitializeComponent()
        {
            // Основні налаштування форми
            this.Text = "PowerShell Terminal";
            this.WindowState = FormWindowState.Maximized;
            this.Size = new Size(1000, 700);

            // Створюємо TabControl
            _mainTabControl = new TabControl();
            _mainTabControl.Dock = DockStyle.Fill;
            this.Controls.Add(_mainTabControl);

            // Створюємо меню
            CreateMenu();
        }

        private void CreateMenu()
        {
            MenuStrip menuStrip = new MenuStrip();

            // File menu
            ToolStripMenuItem fileMenu = new ToolStripMenuItem("File");
            
            ToolStripMenuItem newTabMenu = new ToolStripMenuItem("New Tab");
            newTabMenu.Click += (s, e) => _tabManager.CreateNewTab();
            
            ToolStripMenuItem closeTabMenu = new ToolStripMenuItem("Close Tab");
            closeTabMenu.Click += (s, e) => _tabManager.CloseCurrentTab();
            
            ToolStripMenuItem exitMenu = new ToolStripMenuItem("Exit");
            exitMenu.Click += (s, e) => WinFormsApp.Exit();

            fileMenu.DropDownItems.Add(newTabMenu);
            fileMenu.DropDownItems.Add(closeTabMenu);
            fileMenu.DropDownItems.Add(new ToolStripSeparator());
            fileMenu.DropDownItems.Add(exitMenu);

            // View menu
            ToolStripMenuItem viewMenu = new ToolStripMenuItem("View");
            
            ToolStripMenuItem darkThemeMenu = new ToolStripMenuItem("Dark Theme");
            darkThemeMenu.Click += (s, e) => ApplyDarkTheme();
            
            ToolStripMenuItem lightThemeMenu = new ToolStripMenuItem("Light Theme");
            lightThemeMenu.Click += (s, e) => ApplyLightTheme();

            viewMenu.DropDownItems.Add(darkThemeMenu);
            viewMenu.DropDownItems.Add(lightThemeMenu);

            menuStrip.Items.Add(fileMenu);
            menuStrip.Items.Add(viewMenu);

            this.Controls.Add(menuStrip);
            this.MainMenuStrip = menuStrip;
        }

        private void InitializeApplication()
        {
            // Ініціалізація сервісів
             _historyService = new HistoryService();
            _themeManager = new ThemeManager();
            _tabManager = new TabManager(_mainTabControl, _themeManager, _historyService);

            // Тестуємо з'єднання
              _ = Task.Run(async () =>
                {
                     await Task.Delay(2000); // Даємо час на ініціалізацію
                     await _historyService.TestDatabaseConnection();
                });

                // Створюємо першу вкладку
                _tabManager.CreateNewTab();
        }

        private void ApplyDarkTheme()
        {
            _themeManager.ChangeBackgroundColor(Color.Black);
            _themeManager.ChangeTextColor(Color.Lime);
            ApplyThemeToAllTabs();
        }

        private void ApplyLightTheme()
        {
            _themeManager.ChangeBackgroundColor(Color.White);
            _themeManager.ChangeTextColor(Color.Black);
            ApplyThemeToAllTabs();
        }

        private void ApplyThemeToAllTabs()
        {
            // Буде реалізовано пізніше
        }
    }
}