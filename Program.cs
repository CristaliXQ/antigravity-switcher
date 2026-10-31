using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace AntigravitySwitcher
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    public class AccountProfile
    {
        public string Email { get; set; }
        public string Sub { get; set; }
        public string RawCredential { get; set; }
        public string UserScope { get; set; }
        public string AddedAt { get; set; }
        public string LastUsed { get; set; }
    }

    public static class CredentialManager
    {
        public const string TARGET_NAME = "gemini:antigravity";
        public const string USER_NAME = "antigravity";
        public const uint CRED_TYPE_GENERIC = 1;
        public const uint CRED_PERSIST_LOCAL_MACHINE = 2;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredRead(string target, uint type, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredWrite([In] ref CREDENTIAL userCredential, uint flags);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CredDelete(string target, uint type, int flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern void CredFree(IntPtr credentialPtr);

        public static string ReadCurrentToken()
        {
            IntPtr credPtr;
            if (CredRead(TARGET_NAME, CRED_TYPE_GENERIC, 0, out credPtr))
            {
                try
                {
                    CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
                    if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero)
                    {
                        byte[] blob = new byte[cred.CredentialBlobSize];
                        Marshal.Copy(cred.CredentialBlob, blob, 0, (int)cred.CredentialBlobSize);
                        return Encoding.UTF8.GetString(blob);
                    }
                }
                finally
                {
                    CredFree(credPtr);
                }
            }
            return null;
        }

        public static bool WriteToken(string jsonToken)
        {
            byte[] blob = Encoding.UTF8.GetBytes(jsonToken);
            IntPtr blobPtr = Marshal.AllocHGlobal(blob.Length);
            try
            {
                Marshal.Copy(blob, 0, blobPtr, blob.Length);
                CREDENTIAL cred = new CREDENTIAL();
                cred.Flags = 0;
                cred.Type = CRED_TYPE_GENERIC;
                cred.TargetName = TARGET_NAME;
                cred.Comment = null;
                cred.CredentialBlobSize = (uint)blob.Length;
                cred.CredentialBlob = blobPtr;
                cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
                cred.AttributeCount = 0;
                cred.Attributes = IntPtr.Zero;
                cred.TargetAlias = null;
                cred.UserName = USER_NAME;

                return CredWrite(ref cred, 0);
            }
            finally
            {
                Marshal.FreeHGlobal(blobPtr);
            }
        }

        public static bool DeleteToken()
        {
            return CredDelete(TARGET_NAME, CRED_TYPE_GENERIC, 0);
        }
    }

    public static class AntigravityHelper
    {
        public static string GetExePath()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\antigravity\Antigravity.exe");
        }

        public static string GetRoamingDir()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Antigravity");
        }

        public static string GetProfilesFilePath()
        {
            return Path.Combine(GetRoamingDir(), "antigravity_accounts.json");
        }

        public static string ComputeUserScope(string sub)
        {
            if (string.IsNullOrEmpty(sub)) return "";
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(sub));
                StringBuilder sb = new StringBuilder("u");
                for (int i = 0; i < 8; i++)
                {
                    sb.Append(hash[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        public static bool ParseTokenDetails(string jsonRaw, out string email, out string sub)
        {
            email = null;
            sub = null;
            if (string.IsNullOrEmpty(jsonRaw)) return false;

            try
            {
                var js = new JavaScriptSerializer();
                var root = js.Deserialize<Dictionary<string, object>>(jsonRaw);
                string idToken = null;

                if (root.ContainsKey("id_token") && root["id_token"] != null)
                {
                    idToken = Convert.ToString(root["id_token"]);
                }
                else if (root.ContainsKey("token") && root["token"] is Dictionary<string, object>)
                {
                    var tokenDict = (Dictionary<string, object>)root["token"];
                    if (tokenDict.ContainsKey("id_token") && tokenDict["id_token"] != null)
                    {
                        idToken = Convert.ToString(tokenDict["id_token"]);
                    }
                }

                if (!string.IsNullOrEmpty(idToken))
                {
                    string[] parts = idToken.Split('.');
                    if (parts.Length >= 2)
                    {
                        string payload = parts[1].Replace('-', '+').Replace('_', '/');
                        switch (payload.Length % 4)
                        {
                            case 2: payload += "=="; break;
                            case 3: payload += "="; break;
                        }
                        byte[] bytes = Convert.FromBase64String(payload);
                        string jwtJson = Encoding.UTF8.GetString(bytes);
                        var claims = js.Deserialize<Dictionary<string, object>>(jwtJson);
                        if (claims.ContainsKey("email") && claims["email"] != null)
                            email = Convert.ToString(claims["email"]);
                        if (claims.ContainsKey("sub") && claims["sub"] != null)
                            sub = Convert.ToString(claims["sub"]);
                    }
                }

                if (string.IsNullOrEmpty(email) && root.ContainsKey("email"))
                {
                    email = Convert.ToString(root["email"]);
                }

                return !string.IsNullOrEmpty(email);
            }
            catch
            {
                return false;
            }
        }

        public static string GetAntigravityArguments()
        {
            try
            {
                string[] shortcutPaths = new string[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "Antigravity.lnk"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Antigravity.lnk"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "Antigravity.lnk")
                };

                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType != null)
                {
                    dynamic shell = Activator.CreateInstance(shellType);
                    foreach (var path in shortcutPaths)
                    {
                        if (File.Exists(path))
                        {
                            dynamic sc = shell.CreateShortcut(path);
                            string args = sc.Arguments;
                            if (!string.IsNullOrEmpty(args))
                            {
                                return args;
                            }
                        }
                    }
                }
            }
            catch {}
            return "--proxy-server=\"socks5://127.0.0.1:10807\"";
        }

        public static void StopAntigravity()
        {
            // Мгновенное завершение всех связанных процессов Antigravity и language_server
            foreach (var name in new string[] { "language_server", "Antigravity" })
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try
                    {
                        p.Kill();
                    }
                    catch {}
                }
            }

            // Минимальное ожидание освобождения дескрипторов (до 300 мс)
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < 300)
            {
                if (Process.GetProcessesByName("Antigravity").Length == 0 &&
                    Process.GetProcessesByName("language_server").Length == 0)
                {
                    break;
                }
                Thread.Sleep(20);
            }
        }

        public static void StartAntigravity()
        {
            string exe = GetExePath();
            if (File.Exists(exe))
            {
                string args = GetAntigravityArguments();
                Process.Start(new ProcessStartInfo
                {
                    FileName = exe,
                    Arguments = args,
                    WorkingDirectory = Path.GetDirectoryName(exe),
                    UseShellExecute = true
                });
            }
        }

        public static void UpdateScopeFile(string scope)
        {
            try
            {
                string scopePath = Path.Combine(GetRoamingDir(), "credential-user-scope");
                if (!string.IsNullOrEmpty(scope))
                {
                    File.WriteAllText(scopePath, scope, new UTF8Encoding(false));
                }
                else if (File.Exists(scopePath))
                {
                    File.Delete(scopePath);
                }
            }
            catch {}
        }

        public static void UpdateAppStorage(string email)
        {
            try
            {
                string storagePath = Path.Combine(GetRoamingDir(), "app_storage.json");
                if (File.Exists(storagePath) && !string.IsNullOrEmpty(email))
                {
                    string text = File.ReadAllText(storagePath, Encoding.UTF8);
                    string pattern = @"\""jetski\.onboarding\.lastLoginUsername\"":\s*\""[^\""]*\""";
                    string replacement = "\"jetski.onboarding.lastLoginUsername\": \"" + email + "\"";
                    if (Regex.IsMatch(text, pattern))
                    {
                        text = Regex.Replace(text, pattern, replacement);
                    }
                    else
                    {
                        int lastBrace = text.LastIndexOf('}');
                        if (lastBrace > 0)
                        {
                            string insert = ",\n  \"jetski.onboarding.lastLoginUsername\": \"" + email + "\"\n}";
                            text = text.Substring(0, lastBrace) + insert;
                        }
                    }
                    File.WriteAllText(storagePath, text, new UTF8Encoding(false));
                }
            }
            catch {}
        }

        public static List<AccountProfile> LoadProfiles()
        {
            string path = GetProfilesFilePath();
            if (File.Exists(path))
            {
                try
                {
                    string json = File.ReadAllText(path, Encoding.UTF8);
                    var js = new JavaScriptSerializer();
                    var list = js.Deserialize<List<AccountProfile>>(json);
                    if (list != null) return list;
                }
                catch {}
            }
            return new List<AccountProfile>();
        }

        public static void SaveProfiles(List<AccountProfile> list)
        {
            try
            {
                string path = GetProfilesFilePath();
                string dir = Path.GetDirectoryName(path);
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

                var js = new JavaScriptSerializer();
                string json = js.Serialize(list);
                File.WriteAllText(path, json, new UTF8Encoding(false));
            }
            catch {}
        }
    }

    public class MainForm : Form
    {
        private Label lblHeaderTitle;
        private Label lblHeaderSub;
        private Panel pnlActive;
        private Label lblActiveTitle;
        private Label lblActiveEmail;
        private Label lblActiveScope;
        private Button btnSaveCurrent;

        private Label lblListTitle;
        private ListView lvProfiles;
        private ContextMenuStrip contextMenu;
        private Button btnSwitch;
        private Button btnAddNew;
        private Button btnImportToken;
        private Button btnDelete;
        private Button btnRefresh;
        private Label lblStatus;
        private System.Windows.Forms.Timer pollTimer;

        private string currentTokenRaw = null;
        private string currentEmail = null;
        private string currentScope = null;
        private bool isAwaitingLogin = false;

        public MainForm()
        {
            InitializeComponent();
            ApplyTheme();
            RefreshAllState();

            pollTimer = new System.Windows.Forms.Timer();
            pollTimer.Interval = 2000;
            pollTimer.Tick += (s, e) => PollCredentialState();
            pollTimer.Start();
        }

        private void InitializeComponent()
        {
            this.Text = "Antigravity Account Switcher";
            this.Size = new Size(580, 680);
            this.MinimumSize = new Size(540, 600);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

            try
            {
                string icoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app.ico");
                if (File.Exists(icoPath))
                {
                    this.Icon = new Icon(icoPath);
                }
            }
            catch {}

            lblHeaderTitle = new Label
            {
                Text = "Antigravity Account Switcher",
                Font = new Font("Segoe UI", 14f, FontStyle.Bold),
                Location = new Point(20, 16),
                AutoSize = true
            };

            lblHeaderSub = new Label
            {
                Text = "Быстрое переключение Google-аккаунтов без повторной авторизации",
                Font = new Font("Segoe UI", 9f, FontStyle.Regular),
                Location = new Point(22, 45),
                AutoSize = true
            };

            pnlActive = new Panel
            {
                Location = new Point(20, 75),
                Size = new Size(524, 95),
                BorderStyle = BorderStyle.FixedSingle
            };

            lblActiveTitle = new Label
            {
                Text = "ТЕКУЩИЙ АКТИВНЫЙ АККАУНТ В ANTIGRAVITY:",
                Font = new Font("Segoe UI", 8f, FontStyle.Bold),
                Location = new Point(12, 10),
                AutoSize = true
            };

            lblActiveEmail = new Label
            {
                Text = "Определение...",
                Font = new Font("Segoe UI", 12f, FontStyle.Bold),
                Location = new Point(12, 30),
                Size = new Size(360, 26)
            };

            lblActiveScope = new Label
            {
                Text = "Scope: -",
                Font = new Font("Segoe UI", 8.5f, FontStyle.Regular),
                Location = new Point(13, 60),
                Size = new Size(360, 20)
            };

            btnSaveCurrent = new Button
            {
                Text = "💾 Сохранить",
                Location = new Point(385, 26),
                Size = new Size(125, 42),
                Cursor = Cursors.Hand
            };
            btnSaveCurrent.Click += (s, e) => SaveCurrentAccountAction();

            pnlActive.Controls.Add(lblActiveTitle);
            pnlActive.Controls.Add(lblActiveEmail);
            pnlActive.Controls.Add(lblActiveScope);
            pnlActive.Controls.Add(btnSaveCurrent);

            lblListTitle = new Label
            {
                Text = "Сохраненные аккаунты:",
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                Location = new Point(20, 185),
                AutoSize = true
            };

            lvProfiles = new ListView
            {
                Location = new Point(20, 212),
                Size = new Size(524, 250),
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = false,
                GridLines = true
            };
            lvProfiles.Columns.Add("Email аккаунта", 260);
            lvProfiles.Columns.Add("Статус", 110);
            lvProfiles.Columns.Add("Последнее исп.", 130);

            contextMenu = new ContextMenuStrip();
            var miSwitch = new ToolStripMenuItem("⚡ Переключить на этот аккаунт");
            miSwitch.Click += (s, e) => { if (btnSwitch.Enabled) SwitchAccountAction(); };
            var miDelete = new ToolStripMenuItem("🗑 Удалить из списка");
            miDelete.Click += (s, e) => DeleteProfileAction();
            contextMenu.Items.Add(miSwitch);
            contextMenu.Items.Add(new ToolStripSeparator());
            contextMenu.Items.Add(miDelete);
            lvProfiles.ContextMenuStrip = contextMenu;

            btnSwitch = new Button
            {
                Text = "⚡ ПЕРЕКЛЮЧИТЬ И ПЕРЕЗАПУСТИТЬ",
                Location = new Point(20, 474),
                Size = new Size(524, 46),
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Enabled = false
            };
            btnSwitch.Click += (s, e) => SwitchAccountAction();

            btnAddNew = new Button
            {
                Text = "➕ Добавить через вход",
                Location = new Point(20, 530),
                Size = new Size(170, 36),
                Cursor = Cursors.Hand
            };
            btnAddNew.Click += (s, e) => AddNewViaLoginAction();

            btnImportToken = new Button
            {
                Text = "📋 Вставить токен (JSON)",
                Location = new Point(197, 530),
                Size = new Size(170, 36),
                Cursor = Cursors.Hand
            };
            btnImportToken.Click += (s, e) => ImportTokenAction();

            btnDelete = new Button
            {
                Text = "🗑 Удалить профиль",
                Location = new Point(374, 530),
                Size = new Size(170, 36),
                Cursor = Cursors.Hand,
                Enabled = false
            };
            btnDelete.Click += (s, e) => DeleteProfileAction();

            btnRefresh = new Button
            {
                Text = "🔄 Обновить",
                Location = new Point(434, 180),
                Size = new Size(110, 26),
                Font = new Font("Segoe UI", 8.5f, FontStyle.Regular),
                Cursor = Cursors.Hand
            };
            btnRefresh.Click += (s, e) => RefreshAllState();

            lblStatus = new Label
            {
                Text = "Готов к работе. Двойной клик по аккаунту переключает Antigravity.",
                Font = new Font("Segoe UI", 9f, FontStyle.Italic),
                Location = new Point(20, 580),
                Size = new Size(524, 40)
            };

            this.Controls.Add(lblHeaderTitle);
            this.Controls.Add(lblHeaderSub);
            this.Controls.Add(pnlActive);
            this.Controls.Add(lblListTitle);
            this.Controls.Add(btnRefresh);
            this.Controls.Add(lvProfiles);
            this.Controls.Add(btnSwitch);
            this.Controls.Add(btnAddNew);
            this.Controls.Add(btnImportToken);
            this.Controls.Add(btnDelete);
            this.Controls.Add(lblStatus);

            lvProfiles.SelectedIndexChanged += (s, e) => UpdateButtonsState();
            lvProfiles.DoubleClick += (s, e) =>
            {
                if (btnSwitch != null && btnSwitch.Enabled) SwitchAccountAction();
            };
        }

        private void ApplyTheme()
        {
            Color bgDark = Color.FromArgb(28, 28, 28);
            Color bgCard = Color.FromArgb(37, 37, 38);
            Color textLight = Color.FromArgb(235, 235, 235);
            Color textMuted = Color.FromArgb(160, 160, 160);
            Color accentBlue = Color.FromArgb(0, 122, 204);
            Color btnBg = Color.FromArgb(45, 45, 48);

            this.BackColor = bgDark;
            this.ForeColor = textLight;

            lblHeaderTitle.ForeColor = textLight;
            lblHeaderSub.ForeColor = textMuted;

            pnlActive.BackColor = bgCard;
            lblActiveTitle.ForeColor = textMuted;
            lblActiveEmail.ForeColor = Color.FromArgb(78, 201, 176);
            lblActiveScope.ForeColor = textMuted;

            btnSaveCurrent.BackColor = accentBlue;
            btnSaveCurrent.ForeColor = Color.White;
            btnSaveCurrent.FlatStyle = FlatStyle.Flat;
            btnSaveCurrent.FlatAppearance.BorderSize = 0;

            lblListTitle.ForeColor = textLight;
            btnRefresh.BackColor = btnBg;
            btnRefresh.ForeColor = textLight;
            btnRefresh.FlatStyle = FlatStyle.Flat;
            btnRefresh.FlatAppearance.BorderSize = 0;

            lvProfiles.BackColor = bgCard;
            lvProfiles.ForeColor = textLight;
            lvProfiles.BorderStyle = BorderStyle.FixedSingle;

            btnSwitch.BackColor = Color.FromArgb(16, 124, 65);
            btnSwitch.ForeColor = Color.White;
            btnSwitch.FlatStyle = FlatStyle.Flat;
            btnSwitch.FlatAppearance.BorderSize = 0;

            btnAddNew.BackColor = btnBg;
            btnAddNew.ForeColor = textLight;
            btnAddNew.FlatStyle = FlatStyle.Flat;
            btnAddNew.FlatAppearance.BorderSize = 0;

            btnImportToken.BackColor = btnBg;
            btnImportToken.ForeColor = textLight;
            btnImportToken.FlatStyle = FlatStyle.Flat;
            btnImportToken.FlatAppearance.BorderSize = 0;

            btnDelete.BackColor = Color.FromArgb(140, 30, 30);
            btnDelete.ForeColor = Color.White;
            btnDelete.FlatStyle = FlatStyle.Flat;
            btnDelete.FlatAppearance.BorderSize = 0;

            lblStatus.ForeColor = textMuted;
        }

        private void PollCredentialState()
        {
            string raw = CredentialManager.ReadCurrentToken();
            if (raw != currentTokenRaw)
            {
                currentTokenRaw = raw;
                string email, sub;
                if (AntigravityHelper.ParseTokenDetails(raw, out email, out sub))
                {
                    currentEmail = email;
                    currentScope = AntigravityHelper.ComputeUserScope(sub);

                    // Авто-обновление сохраненного профиля при обновлении токена
                    AutoSaveDetectedAccount(email, sub, raw, currentScope);

                    if (isAwaitingLogin)
                    {
                        isAwaitingLogin = false;
                        SetStatus("✅ Новый аккаунт " + email + " успешно обнаружен и зафиксирован!");
                        MessageBox.Show(this, "Новый аккаунт успешно авторизован и сохранен:\n\n" + email, "Авторизация завершена", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
                else
                {
                    currentEmail = null;
                    currentScope = null;
                }
                UpdateActiveDisplay();
                ReloadProfilesList();
            }
        }

        private void RefreshAllState()
        {
            currentTokenRaw = CredentialManager.ReadCurrentToken();
            string email, sub;
            if (AntigravityHelper.ParseTokenDetails(currentTokenRaw, out email, out sub))
            {
                currentEmail = email;
                currentScope = AntigravityHelper.ComputeUserScope(sub);

                var profiles = AntigravityHelper.LoadProfiles();
                if (profiles.Count == 0)
                {
                    AutoSaveDetectedAccount(email, sub, currentTokenRaw, currentScope);
                }
            }
            else
            {
                currentEmail = null;
                currentScope = null;
            }

            UpdateActiveDisplay();
            ReloadProfilesList();
            SetStatus("Данные актуализированы.");
        }

        private void UpdateActiveDisplay()
        {
            if (!string.IsNullOrEmpty(currentEmail))
            {
                lblActiveEmail.Text = currentEmail;
                lblActiveEmail.ForeColor = Color.FromArgb(78, 201, 176);
                lblActiveScope.Text = "Scope ID: " + (currentScope ?? "не задан");
                btnSaveCurrent.Enabled = true;
            }
            else
            {
                lblActiveEmail.Text = "Не авторизован (ожидание входа)";
                lblActiveEmail.ForeColor = Color.FromArgb(244, 71, 71);
                lblActiveScope.Text = "Ожидание авторизации через Google...";
                btnSaveCurrent.Enabled = false;
            }
        }

        private void ReloadProfilesList()
        {
            var profiles = AntigravityHelper.LoadProfiles();
            lvProfiles.Items.Clear();

            foreach (var p in profiles)
            {
                var item = new ListViewItem(p.Email);
                bool isActive = (!string.IsNullOrEmpty(currentEmail) && string.Equals(p.Email, currentEmail, StringComparison.OrdinalIgnoreCase));
                item.SubItems.Add(isActive ? "🟢 [АКТИВЕН]" : "⚪ Сохранен");
                item.SubItems.Add(p.LastUsed ?? p.AddedAt ?? "-");
                item.Tag = p;

                if (isActive)
                {
                    item.ForeColor = Color.FromArgb(78, 201, 176);
                }
                lvProfiles.Items.Add(item);
            }

            UpdateButtonsState();
        }

        private void UpdateButtonsState()
        {
            if (lvProfiles == null || btnSwitch == null || btnDelete == null) return;

            bool hasSelection = (lvProfiles.SelectedItems.Count > 0);
            btnDelete.Enabled = hasSelection;

            if (hasSelection)
            {
                var p = (AccountProfile)lvProfiles.SelectedItems[0].Tag;
                bool isCurrent = (!string.IsNullOrEmpty(currentEmail) && string.Equals(p.Email, currentEmail, StringComparison.OrdinalIgnoreCase));
                btnSwitch.Enabled = !isCurrent;
                if (isCurrent)
                {
                    btnSwitch.Text = "ВЫБРАННЫЙ АККАУНТ УЖЕ АКТИВЕН";
                    btnSwitch.BackColor = Color.FromArgb(45, 45, 48);
                }
                else
                {
                    btnSwitch.Text = "⚡ ПЕРЕКЛЮЧИТЬ НА: " + p.Email;
                    btnSwitch.BackColor = Color.FromArgb(16, 124, 65);
                }
            }
            else
            {
                btnSwitch.Enabled = false;
                btnSwitch.Text = "⚡ ВЫБЕРИТЕ АККАУНТ ИЗ СПИСКА";
                btnSwitch.BackColor = Color.FromArgb(45, 45, 48);
            }
        }

        private void AutoSaveDetectedAccount(string email, string sub, string raw, string scope)
        {
            var profiles = AntigravityHelper.LoadProfiles();
            var existing = profiles.Find(x => string.Equals(x.Email, email, StringComparison.OrdinalIgnoreCase));
            string now = DateTime.Now.ToString("dd.MM.yyyy HH:mm");

            if (existing != null)
            {
                existing.RawCredential = raw;
                existing.Sub = sub;
                existing.UserScope = scope;
                existing.LastUsed = now;
            }
            else
            {
                profiles.Add(new AccountProfile
                {
                    Email = email,
                    Sub = sub,
                    RawCredential = raw,
                    UserScope = scope,
                    AddedAt = now,
                    LastUsed = now
                });
            }
            AntigravityHelper.SaveProfiles(profiles);
        }

        private void SaveCurrentAccountAction()
        {
            if (string.IsNullOrEmpty(currentTokenRaw) || string.IsNullOrEmpty(currentEmail))
            {
                MessageBox.Show(this, "В данный момент нет активного токена Antigravity для сохранения.", "Предупреждение", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string email, sub;
            AntigravityHelper.ParseTokenDetails(currentTokenRaw, out email, out sub);
            string scope = AntigravityHelper.ComputeUserScope(sub);

            AutoSaveDetectedAccount(email, sub, currentTokenRaw, scope);
            ReloadProfilesList();
            SetStatus("Аккаунт " + email + " сохранен в профили!");
            MessageBox.Show(this, "Аккаунт " + email + " успешно сохранен в менеджер профилей!", "Готово", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void SwitchAccountAction()
        {
            if (lvProfiles.SelectedItems.Count == 0) return;
            var target = (AccountProfile)lvProfiles.SelectedItems[0].Tag;

            SetStatus("⚡ Мгновенное переключение на " + target.Email + "...");
            this.Cursor = Cursors.WaitCursor;
            btnSwitch.Enabled = false;

            try
            {
                // 1. Мгновенное завершение Antigravity
                AntigravityHelper.StopAntigravity();

                // 2. Запись токена в Windows Credential Manager
                bool okCred = CredentialManager.WriteToken(target.RawCredential);
                if (!okCred)
                {
                    MessageBox.Show(this, "Ошибка записи токена в Windows Credential Manager.", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                // 3. Запись scope файла
                AntigravityHelper.UpdateScopeFile(target.UserScope);

                // 4. Обновление app_storage.json
                AntigravityHelper.UpdateAppStorage(target.Email);

                // 5. Обновление времени последнего использования
                target.LastUsed = DateTime.Now.ToString("dd.MM.yyyy HH:mm");
                var profiles = AntigravityHelper.LoadProfiles();
                var p = profiles.Find(x => string.Equals(x.Email, target.Email, StringComparison.OrdinalIgnoreCase));
                if (p != null) p.LastUsed = target.LastUsed;
                AntigravityHelper.SaveProfiles(profiles);

                // 6. Запуск Antigravity с прокси-параметрами из ярлыка
                AntigravityHelper.StartAntigravity();

                RefreshAllState();
                SetStatus("✅ Переключено на " + target.Email + "! Antigravity запущен с прокси.");
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }

        private void AddNewViaLoginAction()
        {
            // Фиксация текущего аккаунта
            if (!string.IsNullOrEmpty(currentEmail) && !string.IsNullOrEmpty(currentTokenRaw))
            {
                string em, sub;
                AntigravityHelper.ParseTokenDetails(currentTokenRaw, out em, out sub);
                AutoSaveDetectedAccount(em, sub, currentTokenRaw, AntigravityHelper.ComputeUserScope(sub));
            }

            SetStatus("Сброс сессии для входа в новый аккаунт...");
            this.Cursor = Cursors.WaitCursor;

            try
            {
                AntigravityHelper.StopAntigravity();
                CredentialManager.DeleteToken();
                AntigravityHelper.UpdateScopeFile(null);
                isAwaitingLogin = true;

                SetStatus("⏳ Запуск Antigravity... Авторизуйтесь в браузере под новой почтой.");
                AntigravityHelper.StartAntigravity();
                RefreshAllState();
            }
            finally
            {
                this.Cursor = Cursors.Default;
            }
        }

        private void ImportTokenAction()
        {
            using (var dlg = new Form())
            {
                dlg.Text = "Импорт токена (JSON)";
                dlg.Size = new Size(500, 380);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.BackColor = Color.FromArgb(28, 28, 28);
                dlg.ForeColor = Color.FromArgb(235, 235, 235);
                dlg.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

                var lbl = new Label
                {
                    Text = "Вставьте JSON токена (содержимое gemini:antigravity с id_token):",
                    Location = new Point(16, 14),
                    Size = new Size(450, 24)
                };

                var txt = new TextBox
                {
                    Multiline = true,
                    ScrollBars = ScrollBars.Vertical,
                    Location = new Point(16, 42),
                    Size = new Size(450, 220),
                    BackColor = Color.FromArgb(37, 37, 38),
                    ForeColor = Color.White,
                    BorderStyle = BorderStyle.FixedSingle
                };

                var btnOk = new Button
                {
                    Text = "Импортировать",
                    Location = new Point(236, 280),
                    Size = new Size(130, 36),
                    BackColor = Color.FromArgb(0, 122, 204),
                    ForeColor = Color.White,
                    FlatStyle = FlatStyle.Flat
                };
                btnOk.FlatAppearance.BorderSize = 0;

                var btnCancel = new Button
                {
                    Text = "Отмена",
                    Location = new Point(376, 280),
                    Size = new Size(90, 36),
                    BackColor = Color.FromArgb(45, 45, 48),
                    ForeColor = Color.White,
                    FlatStyle = FlatStyle.Flat
                };
                btnCancel.FlatAppearance.BorderSize = 0;

                btnCancel.Click += (s, e) => dlg.DialogResult = DialogResult.Cancel;
                btnOk.Click += (s, e) =>
                {
                    string json = txt.Text.Trim();
                    string em, sub;
                    if (!AntigravityHelper.ParseTokenDetails(json, out em, out sub))
                    {
                        MessageBox.Show(dlg, "Не удалось извлечь почту и токен из указанного JSON. Убедитесь, что JSON содержит корректный id_token.", "Ошибка валидации", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }

                    string scope = AntigravityHelper.ComputeUserScope(sub);
                    AutoSaveDetectedAccount(em, sub, json, scope);
                    dlg.DialogResult = DialogResult.OK;
                };

                dlg.Controls.Add(lbl);
                dlg.Controls.Add(txt);
                dlg.Controls.Add(btnOk);
                dlg.Controls.Add(btnCancel);

                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    ReloadProfilesList();
                    SetStatus("Токен успешно импортирован!");
                }
            }
        }

        private void DeleteProfileAction()
        {
            if (lvProfiles.SelectedItems.Count == 0) return;
            var target = (AccountProfile)lvProfiles.SelectedItems[0].Tag;

            var res = MessageBox.Show(this,
                "Удалить аккаунт " + target.Email + " из списка сохраненных профилей?",
                "Удаление профиля",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (res == DialogResult.Yes)
            {
                var profiles = AntigravityHelper.LoadProfiles();
                profiles.RemoveAll(x => string.Equals(x.Email, target.Email, StringComparison.OrdinalIgnoreCase));
                AntigravityHelper.SaveProfiles(profiles);
                ReloadProfilesList();
                SetStatus("Аккаунт " + target.Email + " удален из списка.");
            }
        }

        private void SetStatus(string msg)
        {
            lblStatus.Text = msg;
        }

        [STAThread]
        public static void Main()
        {
            try
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainForm());
            }
            catch (Exception ex)
            {
                MessageBox.Show("Ошибка:\n" + ex.Message, "Antigravity Switcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
