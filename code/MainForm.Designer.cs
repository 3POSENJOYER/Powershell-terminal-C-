namespace PowerShellTerminal
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;
        private System.Windows.Forms.RichTextBox terminalBox;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.terminalBox = new System.Windows.Forms.RichTextBox();
            this.SuspendLayout();
            // 
            // terminalBox
            // 
            this.terminalBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.terminalBox.Font = new System.Drawing.Font("Consolas", 12F);
            this.terminalBox.Location = new System.Drawing.Point(0, 0);
            this.terminalBox.Name = "terminalBox";
            this.terminalBox.Size = new System.Drawing.Size(800, 450);
            this.terminalBox.TabIndex = 0;
            this.terminalBox.Text = "";
            this.terminalBox.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.terminalBox.BackColor = System.Drawing.Color.FromArgb(20, 20, 20);
            this.terminalBox.ForeColor = System.Drawing.Color.FromArgb(230, 230, 230);
            this.terminalBox.ScrollBars = RichTextBoxScrollBars.ForcedVertical;
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.terminalBox);
            this.Name = "MainForm";
            this.Text = "PowerShell Terminal";
            this.ResumeLayout(false);

        }
    }
}
