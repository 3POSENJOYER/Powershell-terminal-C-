using System;
using System.Threading.Tasks;
using System.Windows.Forms;
using PowerShellTerminal.Application.Services;
using PowerShellTerminal.Domain.Entities;

namespace PowerShellTerminal
{
    public partial class MainForm : Form
    {
        private TabManager _tabManager;
        private ThemeManager _themeManager;
        private HistoryService _historyService;

        public MainForm()
        {
            InitializeComponent();

            _historyService = new HistoryService();
            _themeManager = new ThemeManager();
            _tabManager = new TabManager(tabControl, _themeManager, _historyService);

            this.Load += MainForm_Load;
        }

        private async void MainForm_Load(object sender, EventArgs e)
        {
            try
            {
                await _tabManager.CreateNewTabAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to create initial terminal: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void newTerminalToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                await _tabManager.CreateNewTabAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to create new terminal: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
