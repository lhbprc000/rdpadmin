// RdpAdmin - the workstation side of RdpBan.
//
// It knows nothing about filters. It keeps a list of servers that sit behind a
// knock door, knocks that door once a day before the first login, writes the
// password into the Windows credential store and then hands the address to
// mstsc. Everything it needs to know about a server is typed in once:
// address, port, account, password, and the knock URL copied from RdpBan's
// own "knock path" window.
//
// Design notes, because they are the expensive ones:
//   * The knock URL is stored whole. Parsing it into host/port/token buys
//     nothing and gives two more fields to get wrong.
//   * The password is a DPAPI blob scoped to the current Windows user. Copying
//     servers.dat to another account yields nothing. It is never written to a
//     log, never put on a command line: mstsc gets it through CredWrite,
//     the same place rundll32's "remember me" checkbox writes it.
//   * "First time today" is a date string per server. A knock that fails
//     leaves the date alone, so the next attempt knocks again instead of
//     quietly connecting into a closed port.
//   * The window is plain WinForms with flat buttons in one column, no
//     TabControl: the rdpban console learned that the hard way.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace RdpAdmin
{
    // ------------------------------------------------------------ one server
    internal class Srv
    {
        public string name = "";
        public string host = "";
        public int port = 3389;
        public string user = "";
        public string pass = "";      // plaintext, memory only
        public string knock = "";     // full URL: http://host:port/token
        public string daily = "";     // yyyy-MM-dd of the last successful knock
        public bool admin;            // open it as a console / management session

        public Srv Copy()
        {
            Srv c = new Srv();
            c.name = name;
            c.host = host;
            c.port = port;
            c.user = user;
            c.pass = pass;
            c.knock = knock;
            c.daily = daily;
            c.admin = admin;
            return c;
        }

        public string Addr()
        {
            return host + ":" + port;
        }

        public bool KnockedToday()
        {
            return daily == Today();
        }

        public static string Today()
        {
            DateTime now = DateTime.Now;
            return now.ToString("yyyy-MM-dd");
        }
    }

    // ------------------------------------------------------------ storage
    internal static class SrvFile
    {
        // Losing a server by accident used to be total loss, so the version that is
        // about to be overwritten is copied into backups\ first. Ten slots, and a
        // knock-date-only save must not take one: ten boxes in ten days would push
        // out every list anybody actually wanted back.
        public const int KeepBackups = 10;

        private static List<Srv> list = new List<Srv>();
        private static string file = "";
        private static string dir = "";
        private static bool loaded = false;
        private static string lastError = "";
        private static string backupNote = "";

        public static string LastError() { return lastError; }

        // A missed backup is said out loud: insurance, not a precondition. Shown once.
        public static string BackupNote()
        {
            string s = backupNote;
            backupNote = "";
            return s;
        }

        // RDPADMIN_DIR is the isolation seam, the same idea as the daemon's RDPBAN_DIR;
        // unset means %APPDATA%\RdpAdmin.
        public static string Dir()
        {
            if (dir.Length != 0) { return dir; }
            string o = Environment.GetEnvironmentVariable("RDPADMIN_DIR");
            if (o != null && o.Length != 0) { dir = Path.GetFullPath(o); }
            else
            {
                dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "RdpAdmin");
            }
            return dir;
        }

        public static string BackupDir() { return Path.Combine(Dir(), "backups"); }

        public static string PathOfFile()
        {
            if (file.Length != 0) { return file; }
            try { if (!Directory.Exists(Dir())) { Directory.CreateDirectory(Dir()); } }
            catch (Exception) { }
            file = Path.Combine(Dir(), "servers.dat");
            return file;
        }

        public static List<Srv> All()
        {
            if (!loaded) { Load(); }
            return list;
        }

        public static void Load()
        {
            loaded = true;
            list = new List<Srv>();
            lastError = "";
            string p = PathOfFile();
            if (!File.Exists(p)) { return; }
            try { list = Parse(File.ReadAllText(p, Encoding.UTF8)); }
            catch (Exception ex) { lastError = "\u8bfb\u53d6\u670d\u52a1\u5668\u5217\u8868\u5931\u8d25\uff1a" + ex.Message; }
        }

        // One text, two password spellings: pass= is a DPAPI-sealed blob, pass! is
        // plaintext (the layer inside a passphrase-encrypted pack). The marker lives on
        // the KEY, never guessed from the value: a real password can start with dpapi:.
        public static List<Srv> Parse(string text)
        {
            List<Srv> got = new List<Srv>();
            string[] lines = text.Split('\n');
            Srv cur = null;
            for (int i = 0; i < lines.Length; i++)
            {
                string ln = lines[i].Trim();
                if (ln.Length == 0) { continue; }
                if (ln.StartsWith("#")) { continue; }
                if (ln == "[s]")
                {
                    cur = new Srv();
                    got.Add(cur);
                    continue;
                }
                if (cur == null) { continue; }
                int eq = ln.IndexOf('=');
                if (eq <= 0) { continue; }
                string k = ln.Substring(0, eq).Trim();
                string v = ln.Substring(eq + 1).Trim();
                if (k == "name") { cur.name = v; }
                else if (k == "host") { cur.host = v; }
                else if (k == "port") { cur.port = Num(v, 3389); }
                else if (k == "user") { cur.user = v; }
                else if (k == "pass") { cur.pass = Unseal(v); }
                else if (k == "pass!") { cur.pass = v; }
                else if (k == "knock") { cur.knock = v; }
                else if (k == "daily") { cur.daily = v; }
                else if (k == "admin") { cur.admin = (v == "1"); }
            }
            return got;
        }

        public static string Serialize(bool plainPass)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("# RdpAdmin server list.\r\n");
            sb.Append("# Every pass= value is a DPAPI blob bound to this Windows user:\r\n");
            sb.Append("# copying this file to another account decrypts nothing.\r\n");
            for (int i = 0; i < list.Count; i++)
            {
                Srv s = list[i];
                sb.Append("[s]\r\n");
                sb.Append("name=").Append(One(s.name)).Append("\r\n");
                sb.Append("host=").Append(One(s.host)).Append("\r\n");
                sb.Append("port=").Append(s.port.ToString()).Append("\r\n");
                sb.Append("user=").Append(One(s.user)).Append("\r\n");
                if (plainPass) { sb.Append("pass!=").Append(One(s.pass)).Append("\r\n"); }
                else { sb.Append("pass=").Append(Seal(s.pass)).Append("\r\n"); }
                sb.Append("knock=").Append(One(s.knock)).Append("\r\n");
                sb.Append("daily=").Append(One(s.daily)).Append("\r\n");
                sb.Append("admin=").Append(s.admin ? "1" : "0").Append("\r\n");
            }
            return sb.ToString();
        }

        public static bool Save()
        {
            string payload = Serialize(false);
            string p = PathOfFile();
            KeepOldCopy(p, payload);
            try
            {
                using (StreamWriter sw = new StreamWriter(p, false, new UTF8Encoding(false)))
                {
                    sw.Write(payload);
                }
                lastError = "";
                return true;
            }
            catch (Exception ex)
            {
                lastError = "\u5199\u670d\u52a1\u5668\u5217\u8868\u5931\u8d25\uff1a" + ex.Message;
                return false;
            }
        }

        // Keep the version that is about to be overwritten in backups\. Only a
        // difference beyond daily= takes a slot: a knock rewrites one date line and that
        // is not history. Any failure here only writes one sentence; the save proceeds.
        private static void KeepOldCopy(string p, string payload)
        {
            backupNote = "";
            try
            {
                if (!File.Exists(p)) { return; }
                string old = File.ReadAllText(p, Encoding.UTF8);
                if (StripDaily(old) == StripDaily(payload)) { return; }
                string bd = BackupDir();
                if (!Directory.Exists(bd)) { Directory.CreateDirectory(bd); }
                string dst = Path.Combine(bd, "servers-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".dat");
                File.Copy(p, dst, true);
                string[] all = Directory.GetFiles(bd, "servers-*.dat");
                // The file name is the timestamp, so ordinal order is time order.
                Array.Sort(all);
                for (int i = 0; i < all.Length - KeepBackups; i++)
                {
                    try { File.Delete(all[i]); } catch (Exception) { }
                }
            }
            catch (Exception ex)
            {
                backupNote = "\u7559\u5e95\u6ca1\u505a\u6210\uff1a" + ex.Message + "\uff08\u5217\u8868\u7167\u5e38\u4fdd\u5b58\uff09";
            }
        }

        private static string StripDaily(string text)
        {
            string[] lines = text.Split('\n');
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < lines.Length; i++)
            {
                string ln = lines[i].Trim();
                if (ln.StartsWith("daily=")) { continue; }
                sb.Append(ln).Append("\n");
            }
            return sb.ToString();
        }

        // Newest first, for the restore dialog. The row count is [s] counting: no decrypt.
        public static string[] BackupsNewestFirst()
        {
            try
            {
                string bd = BackupDir();
                if (!Directory.Exists(bd)) { return new string[0]; }
                string[] all = Directory.GetFiles(bd, "servers-*.dat");
                Array.Sort(all);
                Array.Reverse(all);
                return all;
            }
            catch (Exception) { return new string[0]; }
        }

        public static int CountOf(string text)
        {
            try { return Parse(text).Count; }
            catch (Exception) { return -1; }
        }

        public static void SetList(List<Srv> next)
        {
            list = next;
            loaded = true;
        }


        public static int Num(string s, int dflt)
        {
            try
            {
                int n = Convert.ToInt32(s);
                if (n > 0 && n < 65536) { return n; }
            }
            catch (Exception) { }
            return dflt;
        }

        private static string One(string s)
        {
            if (s == null) { return ""; }
            return s.Replace("\r", " ").Replace("\n", " ");
        }

        private static string Seal(string plain)
        {
            if (plain == null || plain.Length == 0) { return ""; }
            try
            {
                byte[] b = Encoding.UTF8.GetBytes(plain);
                byte[] c = ProtectedData.Protect(b, null, DataProtectionScope.CurrentUser);
                return "dpapi:" + Convert.ToBase64String(c);
            }
            catch (Exception) { return ""; }
        }

        private static string Unseal(string stored)
        {
            if (stored == null || stored.Length == 0) { return ""; }
            if (!stored.StartsWith("dpapi:")) { return ""; }
            try
            {
                byte[] c = Convert.FromBase64String(stored.Substring(6));
                byte[] b = ProtectedData.Unprotect(c, null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(b);
            }
            catch (Exception) { return ""; }
        }
    }

    // ------------------------------------------------------------ the knock
    internal static class Knock
    {
        // Returns "" when the door opened, otherwise a sentence the operator
        // can act on. The door answers 200 with a three-line page, and 403 with
        // an empty body for anything it does not recognise.
        public static string Hit(Srv s)
        {
            string url = (s.knock == null ? "" : s.knock.Trim());
            if (url.Length == 0) { return "\u8fd9\u53f0\u6ca1\u6709\u586b\u6572\u95e8 URL"; }
            if (url.IndexOf("<this box>") >= 0) { url = url.Replace("<this box>", s.host); }
            HttpWebResponse res = null;
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "GET";
                req.Timeout = 6000;
                req.ReadWriteTimeout = 6000;
                req.KeepAlive = false;
                req.Proxy = null;
                req.UserAgent = "RdpAdmin";
                res = (HttpWebResponse)req.GetResponse();
                int code = (int)res.StatusCode;
                string body = "";
                using (StreamReader rd = new StreamReader(res.GetResponseStream(), Encoding.UTF8))
                {
                    body = rd.ReadToEnd();
                }
                res.Close();
                res = null;
                if (code != 200) { return "\u6572\u95e8\u7aef\u53e3\u56de\u4e86 HTTP " + code; }
                if (body.IndexOf("Connect to") < 0)
                {
                    return "\u6572\u95e8\u7aef\u53e3\u56de\u4e86 200\uff0c\u4f46\u5185\u5bb9\u4e0d\u662f\u6572\u95e8\u9875\uff1a\u7aef\u53e3\u586b\u6210\u4e86\u522b\u7684\u670d\u52a1\uff1f";
                }
                return "";
            }
            catch (WebException we)
            {
                HttpWebResponse err = we.Response as HttpWebResponse;
                if (err != null)
                {
                    int code = (int)err.StatusCode;
                    err.Close();
                    if (code == 403)
                    {
                        return "\u670d\u52a1\u5668\u56de\u4e86 403\uff1a\u6572\u95e8\u8def\u5f84\u4e0d\u5bf9\uff0c\u6216\u8005\u8fd9\u53f0\u7684\u5b88\u62a4\u8fdb\u7a0b\u6ca1\u5f00\u7740\u6572\u95e8\u95e8";
                    }
                    return "\u6572\u95e8\u7aef\u53e3\u56de\u4e86 HTTP " + code;
                }
                if (we.Status == WebExceptionStatus.Timeout)
                {
                    return "\u6572\u95e8\u7aef\u53e3 6 \u79d2\u6ca1\u6709\u5e94\u7b54\uff1a\u5b88\u62a4\u8fdb\u7a0b\u6ca1\u8dd1\uff0c\u6216\u8005\u7aef\u53e3\u3001\u5730\u5740\u5199\u9519\u4e86";
                }
                if (we.Status == WebExceptionStatus.NameResolutionFailure)
                {
                    return "\u8fd9\u4e2a\u5730\u5740\u89e3\u6790\u4e0d\u4e86\uff08DNS \u6216 IP \u5199\u9519\uff09";
                }
                if (we.Status == WebExceptionStatus.ConnectFailure)
                {
                    return "\u8fde\u4e0d\u4e0a\u6572\u95e8\u7aef\u53e3\uff08\u62d2\u7edd\u8fde\u63a5\uff09\uff1a\u5b88\u62a4\u8fdb\u7a0b\u6ca1\u8dd1\uff0c\u6216\u8005\u7aef\u53e3\u5199\u9519";
                }
                return "\u8fde\u4e0d\u4e0a\u6572\u95e8\u7aef\u53e3\uff1a" + we.Status.ToString();
            }
            catch (Exception ex)
            {
                return "\u6572\u95e8\u51fa\u9519\uff1a" + ex.Message;
            }
            finally
            {
                if (res != null) { try { res.Close(); } catch (Exception) { } }
            }
        }
    }

    // ------------------------------------------------------------ credentials
    // mstsc takes the password from the Windows credential store and nowhere
    // else; it has no command line for it. Writing it here is the same thing
    // cmdkey /generic:TERMSRV/host does, without the password landing in a
    // process command line that anybody can read out of the process list.
    internal static class Cred
    {
        private const int CRED_TYPE_GENERIC = 1;
        private const int CRED_PERSIST_LOCAL_MACHINE = 2;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public int Flags;
            public int Type;
            public string TargetName;
            public string Comment;
            public long LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredWrite(ref CREDENTIAL cred, int flags);

        [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredDelete(string target, int type, int flags);

        public static string Store(Srv s)
        {
            string err = Write("TERMSRV/" + s.host, s.user, s.pass);
            if (err.Length != 0) { return err; }
            // mstsc looks up TERMSRV/host:port when the port is not 3389 on
            // some builds, and TERMSRV/host on others. Write both.
            if (s.port != 3389)
            {
                string err2 = Write("TERMSRV/" + s.host + ":" + s.port.ToString(), s.user, s.pass);
                if (err2.Length != 0) { return err2; }
            }
            return "";
        }

        private static string Write(string target, string user, string pass)
        {
            CREDENTIAL c = new CREDENTIAL();
            byte[] blob = Encoding.Unicode.GetBytes(pass);
            IntPtr mem = Marshal.AllocHGlobal(blob.Length);
            try
            {
                Marshal.Copy(blob, 0, mem, blob.Length);
                c.Type = CRED_TYPE_GENERIC;
                c.TargetName = target;
                c.UserName = user;
                c.Persist = CRED_PERSIST_LOCAL_MACHINE;
                c.CredentialBlobSize = blob.Length;
                c.CredentialBlob = mem;
                if (!CredWrite(ref c, 0))
                {
                    return "\u5199\u51ed\u636e\u5931\u8d25\uff0cWin32 " + Marshal.GetLastWin32Error().ToString();
                }
                return "";
            }
            catch (Exception ex)
            {
                return "\u5199\u51ed\u636e\u51fa\u9519\uff1a" + ex.Message;
            }
            finally
            {
                for (int i = 0; i < blob.Length; i++) { blob[i] = 0; }
                try { Marshal.Copy(blob, 0, mem, blob.Length); } catch (Exception) { }
                Marshal.FreeHGlobal(mem);
            }
        }

        public static void Forget(Srv s)
        {
            try { CredDelete("TERMSRV/" + s.host, CRED_TYPE_GENERIC, 0); }
            catch (Exception) { }
            try { CredDelete("TERMSRV/" + s.host + ":" + s.port.ToString(), CRED_TYPE_GENERIC, 0); }
            catch (Exception) { }
        }
    }

    // ------------------------------------------------------------ launch
    internal static class Launch
    {
        // "" when mstsc was started (or when the test hook said not to).
        // "admin" is mstsc's /admin: the console session, what a server 2008
        // box needs for anything the session manager usually hides.
        public static string Go(Srv s, bool admin, out string note)
        {
            note = "";
            if (s.user.Length != 0 && s.pass.Length != 0)
            {
                string err = Cred.Store(s);
                if (err.Length != 0)
                {
                    note = "\u5bc6\u7801\u6ca1\u5199\u8fdb Windows \u51ed\u636e\uff0c" + err + "\uff1b\u8fdc\u7a0b\u684c\u9762\u4f1a\u8981\u4f60\u624b\u8f93";
                }
            }
            else
            {
                note = "\u8fd9\u53f0\u6ca1\u6709\u5b58\u8d26\u6237\u5bc6\u7801\uff0c\u8fdc\u7a0b\u684c\u9762\u4f1a\u8981\u4f60\u624b\u8f93";
            }
            if (Environment.GetEnvironmentVariable("RDPADMIN_NOLAUNCH") == "1")
            {
                note = "\u6d4b\u8bd5\u6a21\u5f0f\uff1a\u6ca1\u6709\u542f\u52a8 mstsc";
                return "";
            }
            string exe = Path.Combine(Environment.SystemDirectory, "mstsc.exe");
            if (!File.Exists(exe)) { return "\u627e\u4e0d\u5230 " + exe; }
            try
            {
                Process.Start(exe, "/v:" + s.host + ":" + s.port.ToString() +
                    (admin ? " /admin" : ""));
            }
            catch (Exception ex)
            {
                return "\u542f\u52a8\u8fdc\u7a0b\u684c\u9762\u5931\u8d25\uff1a" + ex.Message;
            }
            return "";
        }
    }

    // ------------------------------------------------------------ edit dialog
    internal class EditForm : Form
    {
        public Srv Result;
        private TextBox tName;
        private TextBox tHost;
        private TextBox tPort;
        private TextBox tUser;
        private TextBox tPass;
        private TextBox tKnock;
        private CheckBox adminCheck;
        private Button eyeBtn;
        private Button copyBtn;
        private System.Windows.Forms.Timer copyTimer;
        // The name is what the list shows, the address is what gets dialled. If
        // one of them is still blank while you type in the other, it fills in
        // with the same text and keeps following. Once you type something of
        // your own into a field it stops being a copy, and clearing the field
        // you are typing in never wipes the other one. syncing only blocks the
        // TextChanged loop caused by writing Text from here; it is not UI state.
        private bool syncing;
        private bool autoName;
        private bool autoHost;

        public EditForm(Srv s)
        {
            Text = (s == null ? "\u6dfb\u52a0\u670d\u52a1\u5668" : "\u7f16\u8f91\u670d\u52a1\u5668");
            ClientSize = new Size(700, 476);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            Font = MainForm.UiFont();
            BackColor = Color.White;

            Srv v = (s == null ? new Srv() : s.Copy());

            Label head = new Label();
            head.Text = "\u586b\u4e00\u6b21\uff0c\u4ee5\u540e\u70b9\u300e\u8fde\u63a5\u300f\u5c31\u591f";
            head.Font = new Font(MainForm.UiFont().FontFamily, 11F, FontStyle.Bold);
            head.ForeColor = Color.FromArgb(40, 45, 50);
            head.SetBounds(24, 16, 420, 24);
            Controls.Add(head);

            tName = Row("\u540d\u79f0", 56, v.name);
            tHost = Row("\u5730\u5740", 106, v.host);
            tPort = Row("\u8fdc\u7a0b\u7aef\u53e3", 156, v.port.ToString());
            tUser = Row("\u767b\u5f55\u8d26\u6237", 206, v.user);
            tPass = PassRow(256, v.pass);
            tKnock = Row("\u6572\u95e8 URL", 306, v.knock);

            adminCheck = new CheckBox();
            adminCheck.Text = "\u4ee5\u7ba1\u7406\u4f1a\u8bdd\u8fde\u63a5\uff08/admin\uff09";
            adminCheck.SetBounds(126, 336, 420, 22);
            adminCheck.Checked = v.admin;
            Controls.Add(adminCheck);

            Label hint = new Label();
            hint.Text = "\u5bc6\u7801\u7559\u7a7a\u7684\u8bdd\uff0c\u8fde\u63a5\u65f6\u7531\u8fdc\u7a0b\u684c\u9762\u81ea\u5df1\u5f39\u7a97\u8981\u4f60\u8f93\u3002\r\n" +
                        "\u6572\u95e8 URL \u4ece\u670d\u52a1\u5668\u90a3\u53f0\u7684\u300e\u6572\u95e8\u8def\u5f84\u300f\u7a97\u53e3\u6574\u6761\u590d\u5236\u8fc7\u6765\uff0c\u5f62\u5982\r\n" +
                        "http://\u5730\u5740:\u7aef\u53e3/\u8def\u5f84";
            hint.ForeColor = Color.FromArgb(110, 115, 120);
            hint.SetBounds(126, 362, 548, 58);
            Controls.Add(hint);

            Button ok = MainForm.Flat("\u4fdd\u5b58", 96, Color.FromArgb(0, 122, 204), Color.White);
            ok.SetBounds(586, 426, 96, 32);
            ok.DialogResult = DialogResult.None;
            ok.Click += new EventHandler(OnOk);
            Controls.Add(ok);

            Button cancel = MainForm.Flat("\u53d6\u6d88", 96, Color.FromArgb(240, 242, 245), Color.FromArgb(40, 45, 50));
            cancel.SetBounds(482, 426, 96, 32);
            cancel.DialogResult = DialogResult.Cancel;
            Controls.Add(cancel);

            AcceptButton = ok;
            CancelButton = cancel;

            // The two fields are the same thing said twice - the address is what
            // gets dialled, the name is what the list shows. Typing one while the
            // other is blank fills it in; the copy stops as soon as somebody
            // types something different into it.
            tName.TextChanged += new EventHandler(OnNameText);
            tHost.TextChanged += new EventHandler(OnHostText);
        }

        private void OnNameText(object sender, EventArgs e)
        {
            if (syncing) { return; }
            // a real keystroke here: the name is not a copy of the address any more
            autoName = false;
            syncing = true;
            try
            {
                if (tName.Text.Length == 0)
                {
                    // nothing typed yet: just stop following, keep the address as
                    // it stands instead of blanking it
                    autoHost = false;
                }
                else if (autoHost || tHost.Text.Length == 0)
                {
                    tHost.Text = tName.Text;
                    tHost.SelectionStart = tHost.TextLength;
                    autoHost = true;
                }
            }
            finally { syncing = false; }
        }

        private void OnHostText(object sender, EventArgs e)
        {
            if (syncing) { return; }
            // a real keystroke here: the address is not a copy of the name any more
            autoHost = false;
            syncing = true;
            try
            {
                if (tHost.Text.Length == 0)
                {
                    autoName = false;
                }
                else if (autoName || tName.Text.Length == 0)
                {
                    tName.Text = tHost.Text;
                    tName.SelectionStart = tName.TextLength;
                    autoName = true;
                }
            }
            finally { syncing = false; }
        }

        private TextBox Row(string label, int y, string value)
        {
            Label l = new Label();
            l.Text = label;
            l.SetBounds(24, y + 4, 96, 20);
            l.ForeColor = Color.FromArgb(60, 65, 70);
            Controls.Add(l);

            TextBox t = new TextBox();
            t.Text = value;
            t.SetBounds(126, y, 548, 24);
            Controls.Add(t);
            return t;
        }

        // The password row is the only one with company: a mask is all very
        // well until the operator has to type forty characters into a field he
        // cannot read back. Two small buttons - show it, copy it - and the
        // textbox gives up the width they need.
        private TextBox PassRow(int y, string value)
        {
            Label l = new Label();
            l.Text = "\u5bc6\u7801";
            l.SetBounds(24, y + 4, 96, 20);
            l.ForeColor = Color.FromArgb(60, 65, 70);
            Controls.Add(l);

            TextBox t = new TextBox();
            t.Text = value;
            t.UseSystemPasswordChar = true;
            t.SetBounds(126, y, 386, 24);
            Controls.Add(t);

            eyeBtn = MainForm.Flat("\u663e\u793a", 72, Color.FromArgb(246, 248, 250), Color.FromArgb(35, 40, 45));
            eyeBtn.SetBounds(520, y, 72, 24);
            eyeBtn.Click += new EventHandler(OnShowPass);
            Controls.Add(eyeBtn);

            copyBtn = MainForm.Flat("\u590d\u5236", 72, Color.FromArgb(246, 248, 250), Color.FromArgb(35, 40, 45));
            copyBtn.SetBounds(600, y, 72, 24);
            copyBtn.Click += new EventHandler(OnCopyPass);
            Controls.Add(copyBtn);

            copyTimer = new System.Windows.Forms.Timer();
            copyTimer.Interval = 1400;
            copyTimer.Tick += new EventHandler(OnCopyDone);
            return t;
        }

        private void OnShowPass(object sender, EventArgs e)
        {
            tPass.UseSystemPasswordChar = !tPass.UseSystemPasswordChar;
            eyeBtn.Text = tPass.UseSystemPasswordChar ? "\u663e\u793a" : "\u9690\u85cf";
            tPass.Focus();
            if (tPass.Text.Length > 0) { tPass.SelectionStart = tPass.Text.Length; }
        }

        private void OnCopyPass(object sender, EventArgs e)
        {
            if (tPass.Text.Length == 0) { Warn("\u8fd9\u53f0\u7684\u5bc6\u7801\u662f\u7a7a\u7684\uff0c\u6ca1\u6709\u53ef\u590d\u5236\u7684"); return; }
            try { Clipboard.SetText(tPass.Text); }
            catch (Exception ex) { Warn("\u590d\u5236\u5230\u526a\u8d34\u677f\u5931\u8d25\uff1a" + ex.Message); return; }
            copyBtn.Text = "\u5df2\u590d\u5236";
            copyTimer.Start();
        }

        private void OnCopyDone(object sender, EventArgs e)
        {
            copyTimer.Stop();
            copyBtn.Text = "\u590d\u5236";
        }

        private void OnOk(object sender, EventArgs e)
        {
            string name = tName.Text.Trim();
            string host = tHost.Text.Trim();
            if (name.Length == 0) { Warn("\u540d\u79f0\u4e0d\u80fd\u7a7a"); tName.Focus(); return; }
            if (host.Length == 0) { Warn("\u5730\u5740\u4e0d\u80fd\u7a7a"); tHost.Focus(); return; }
            int port = SrvFile.Num(tPort.Text.Trim(), -1);
            if (port < 0) { Warn("\u8fdc\u7a0b\u7aef\u53e3\u8981\u5728 1 \u5230 65535 \u4e4b\u95f4"); tPort.Focus(); return; }

            string knock = tKnock.Text.Trim();
            // "rdpban secret add" prints the host as "<this box>": the box cannot
            // know what name the operator reaches it by. The address field is
            // that answer, so fill it in rather than retyping the URL.
            if (knock.IndexOf("<this box>") >= 0) { knock = knock.Replace("<this box>", host); }
            if (knock.Length != 0)
            {
                if (!knock.StartsWith("http://") && !knock.StartsWith("https://"))
                {
                    knock = "http://" + knock;
                }
                string rest = knock.Substring(knock.IndexOf("//") + 2);
                if (rest.IndexOf('/') < 0)
                {
                    Warn("\u6572\u95e8 URL \u91cc\u6ca1\u6709\u8def\u5f84\uff1a\u5e94\u8be5\u6574\u6761\u662f http://\u5730\u5740:\u7aef\u53e3/\u8def\u5f84");
                    tKnock.Focus();
                    return;
                }
            }

            Srv s = new Srv();
            s.name = name;
            s.host = host;
            s.port = port;
            s.user = tUser.Text.Trim();
            s.pass = tPass.Text;
            s.knock = knock;
            s.daily = "";
            s.admin = adminCheck.Checked;
            Result = s;
            DialogResult = DialogResult.OK;
        }

        private void Warn(string text)
        {
            MessageBox.Show(this, text, "\u586b\u5f97\u4e0d\u5bf9", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    // ------------------------------------------------------------ portable backup
    // Why a second format exists: the DPAPI seal in servers.dat is bound to this
    // machine and this Windows account, and "the box is gone" is the one case a
    // portable backup is actually for. So the plaintext passwords are taken out
    // of memory here and re-sealed under a passphrase the operator types.
    // The file is a credential bundle: besides the passwords it carries every
    // knock URL, which is the door itself. That is why "export the fields but
    // not the passwords" is deliberately not offered - it would buy nothing and
    // it would make the file look safe to forward.
    internal static class BackupPack
    {
        // First line of the plaintext and the only passphrase check. Decrypting
        // with the wrong key usually dies on the padding, but it does not have
        // to, so the answer is judged on this marker, never on an exception.
        private const string Magic = "# RdpAdmin portable backup v1\n";
        private const int Rounds = 120000;
        public const string Suffix = ".rdpadmin-backup";
        public const int MinPass = 8;

        public static string DefaultName()
        {
            return "rdpadmin-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + Suffix;
        }

        private static byte[] RandomBytes(int n)
        {
            byte[] b = new byte[n];
            using (RNGCryptoServiceProvider r = new RNGCryptoServiceProvider())
            {
                r.GetBytes(b);
            }
            return b;
        }

        private static byte[] KeyOf(string pass, byte[] salt, int rounds)
        {
            using (Rfc2898DeriveBytes k = new Rfc2898DeriveBytes(pass, salt, rounds))
            {
                return k.GetBytes(32);
            }
        }

        // "" means written; anything else is one sentence for the operator.
        public static string Export(string path, string pass)
        {
            try
            {
                byte[] salt = RandomBytes(16);
                byte[] iv = RandomBytes(16);
                byte[] body = Encoding.UTF8.GetBytes(Magic + SrvFile.Serialize(true));
                byte[] data;
                AesManaged a = new AesManaged();
                a.Key = KeyOf(pass, salt, Rounds);
                a.IV = iv;
                a.Mode = CipherMode.CBC;
                a.Padding = PaddingMode.PKCS7;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, a.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(body, 0, body.Length);
                        cs.FlushFinalBlock();
                    }
                    data = ms.ToArray();
                }
                a.Clear();
                StringBuilder sb = new StringBuilder();
                sb.Append("RDPADMIN-BACKUP 1\n");
                sb.Append("rounds=").Append(Rounds.ToString()).Append("\n");
                sb.Append("salt=").Append(Convert.ToBase64String(salt)).Append("\n");
                sb.Append("iv=").Append(Convert.ToBase64String(iv)).Append("\n");
                sb.Append("data=").Append(Convert.ToBase64String(data)).Append("\n");
                File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
                return "";
            }
            catch (Exception ex)
            {
                return "\u5199\u4e0d\u51fa\u53bb\uff1a" + ex.Message;
            }
        }

        // A wrong passphrase gives back null and one sentence, and nothing else
        // happens anywhere: half a list imported is worse than none.
        public static List<Srv> Open(string path, string pass, out string err)
        {
            string text;
            try { text = File.ReadAllText(path, Encoding.UTF8); }
            catch (Exception ex)
            {
                err = "\u8bfb\u4e0d\u4e86\u8fd9\u4e2a\u6587\u4ef6\uff1a" + ex.Message;
                return null;
            }
            err = "";
            if (!text.StartsWith("RDPADMIN-BACKUP 1\n"))
            {
                err = "\u8fd9\u4e0d\u662f RdpAdmin \u7684\u5907\u4efd\u6587\u4ef6\u3002";
                return null;
            }
            try
            {
                int rounds = 0;
                string salt = "", iv = "", data = "";
                string[] lines = text.Split('\n');
                for (int i = 1; i < lines.Length; i++)
                {
                    string ln = lines[i].Trim();
                    int eq = ln.IndexOf('=');
                    if (eq <= 0) { continue; }
                    string k = ln.Substring(0, eq);
                    string v = ln.Substring(eq + 1);
                    // Num is the port parser (it caps at 65535), so it would eat 120000 rounds.
                    if (k == "rounds") { int.TryParse(v, out rounds); }
                    else if (k == "salt") { salt = v; }
                    else if (k == "iv") { iv = v; }
                    else if (k == "data") { data = v; }
                }
                // rounds comes from the file: 0 would make PBKDF2 throw an exception
                // that has nothing to do with the passphrase and mislead the operator.
                if (rounds < 1000 || salt.Length == 0 || iv.Length == 0 || data.Length == 0)
                {
                    err = "\u8fd9\u4e0d\u662f RdpAdmin \u7684\u5907\u4efd\u6587\u4ef6\u3002";
                    return null;
                }
                byte[] clear;
                AesManaged a = new AesManaged();
                a.Key = KeyOf(pass, Convert.FromBase64String(salt), rounds);
                a.IV = Convert.FromBase64String(iv);
                a.Mode = CipherMode.CBC;
                a.Padding = PaddingMode.PKCS7;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, a.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        byte[] raw = Convert.FromBase64String(data);
                        cs.Write(raw, 0, raw.Length);
                        cs.FlushFinalBlock();
                    }
                    clear = ms.ToArray();
                }
                a.Clear();
                string plain = Encoding.UTF8.GetString(clear);
                if (!plain.StartsWith(Magic))
                {
                    err = "\u53e3\u4ee4\u4e0d\u5bf9\uff1a\u8fd9\u4efd\u6587\u4ef6\u89e3\u4e0d\u51fa\u4efb\u4f55\u4e1c\u897f\u3002";
                    return null;
                }
                return SrvFile.Parse(plain.Substring(Magic.Length));
            }
            catch (Exception)
            {
                // A wrong key and a broken file are indistinguishable here, and the
                // exception text is localized: "wrong passphrase" is the only useful answer.
                err = "\u53e3\u4ee4\u4e0d\u5bf9\uff1a\u8fd9\u4efd\u6587\u4ef6\u89e3\u4e0d\u51fa\u4efb\u4f55\u4e1c\u897f\u3002";
                return null;
            }
        }
    }

    // ------------------------------------------------------------ export dialog
    internal class BackupForm : Form
    {
        public string OutPath = "";
        public int Count = 0;
        private TextBox p1;
        private TextBox p2;

        public BackupForm(int servers)
        {
            Text = "\u5bfc\u51fa\u5907\u4efd";
            ClientSize = new Size(620, 288);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            Font = MainForm.UiFont();
            BackColor = Color.White;

            Label head = new Label();
            // The count comes first: let him see how many boxes travel before the warning.
            head.Text = servers.ToString() +
                " \u53f0\u670d\u52a1\u5668\u7684\u5730\u5740\u3001\u8d26\u6237\u3001\u53e3\u4ee4\u548c\u6572\u95e8 URL " +
                "\u90fd\u4f1a\u5199\u8fdb\u8fd9\u4e00\u4e2a\u6587\u4ef6\u3002";
            head.ForeColor = Color.FromArgb(40, 45, 50);
            head.SetBounds(24, 16, 572, 40);
            Controls.Add(head);

            p1 = Row("\u53e3\u4ee4", 66, "");
            p2 = Row("\u518d\u8f93\u4e00\u904d", 106, "");

            Label hint = new Label();
            hint.Text = "\u81f3\u5c11 8 \u4e2a\u5b57\u7b26\u3002\u8fd9\u4e2a\u6587\u4ef6\u80fd\u4e0d\u80fd\u7ed9\u522b\u4eba\uff0c" +
                        "\u53ea\u770b\u4f60\u8bbe\u7684\u53e3\u4ee4\uff1b\u53e3\u4ee4\u5fd8\u4e86\u5c31\u6ca1\u6709\u7b2c\u4e8c\u6b21\u3002";
            hint.ForeColor = Color.FromArgb(110, 115, 120);
            hint.SetBounds(126, 138, 470, 40);
            Controls.Add(hint);

            Button go = MainForm.Flat("\u5199\u5230\u2026", 110, Color.FromArgb(0, 122, 204), Color.White);
            go.SetBounds(486, 238, 110, 32);
            go.Click += new EventHandler(OnGo);
            Controls.Add(go);

            Button cancel = MainForm.Flat("\u53d6\u6d88", 96, Color.FromArgb(240, 242, 245), Color.FromArgb(40, 45, 50));
            cancel.SetBounds(382, 238, 96, 32);
            cancel.DialogResult = DialogResult.Cancel;
            Controls.Add(cancel);

            AcceptButton = go;
            CancelButton = cancel;
        }

        // No show-button on the passphrase boxes: the only reader is the person typing,
        // and when the two entries disagree, retyping is cheaper than looking.
        private TextBox Row(string label, int y, string value)
        {
            Label l = new Label();
            l.Text = label;
            l.SetBounds(24, y + 4, 96, 20);
            l.ForeColor = Color.FromArgb(60, 65, 70);
            Controls.Add(l);

            TextBox t = new TextBox();
            t.Text = value;
            t.UseSystemPasswordChar = true;
            t.SetBounds(126, y, 470, 24);
            Controls.Add(t);
            return t;
        }

        private void OnGo(object sender, EventArgs e)
        {
            string a = p1.Text;
            if (a.Length < BackupPack.MinPass)
            {
                Warn("\u53e3\u4ee4\u592a\u77ed\uff1a\u81f3\u5c11 8 \u4e2a\u5b57\u7b26");
                p1.Focus();
                return;
            }
            if (a != p2.Text)
            {
                Warn("\u4e24\u6b21\u53e3\u4ee4\u4e0d\u4e00\u6837");
                p2.Focus();
                return;
            }
            SaveFileDialog d = new SaveFileDialog();
            d.Title = Text;
            d.FileName = BackupPack.DefaultName();
            d.AddExtension = true;
            d.DefaultExt = BackupPack.Suffix;
            d.OverwritePrompt = true;
            d.Filter = "\u5907\u4efd\u6587\u4ef6 (*.rdpadmin-backup)|*.rdpadmin-backup|" +
                       "\u6240\u6709\u6587\u4ef6 (*.*)|*.*";
            if (d.ShowDialog(this) != DialogResult.OK) { return; }
            string err = BackupPack.Export(d.FileName, a);
            p1.Clear();
            p2.Clear();
            if (err.Length != 0) { Warn(err); return; }
            OutPath = d.FileName;
            Count = SrvFile.All().Count;
            DialogResult = DialogResult.OK;
        }

        private void Warn(string text)
        {
            MessageBox.Show(this, text, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    // ------------------------------------------------------------ restore dialog
    internal class RestoreForm : Form
    {
        public bool Did = false;
        public string From = "";
        public int Count = 0;
        private ListView lv;
        private Label emptyHint;

        public RestoreForm()
        {
            Text = "\u6062\u590d\u5217\u8868";
            ClientSize = new Size(740, 424);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            Font = MainForm.UiFont();
            BackColor = Color.White;

            Label head = new Label();
            head.Text = "\u672c\u673a\u7559\u5e95\u53ea\u80fd\u5728\u8fd9\u53f0\u673a\u5668\u3001\u8fd9\u4e2a Windows " +
                        "\u8d26\u53f7\u91cc\u6062\u590d\u3002";
            head.ForeColor = Color.FromArgb(110, 115, 120);
            head.SetBounds(16, 12, 708, 20);
            Controls.Add(head);

            lv = new ListView();
            lv.View = View.Details;
            lv.FullRowSelect = true;
            lv.MultiSelect = false;
            lv.HideSelection = false;
            lv.GridLines = false;
            lv.BorderStyle = BorderStyle.FixedSingle;
            lv.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            lv.SetBounds(16, 38, 708, 300);
            lv.Columns.Add("\u65f6\u95f4", 150, HorizontalAlignment.Left);
            lv.Columns.Add("\u53f0\u6570", 70, HorizontalAlignment.Left);
            lv.Columns.Add("\u6587\u4ef6", 470, HorizontalAlignment.Left);
            lv.DoubleClick += new EventHandler(OnUse);
            Controls.Add(lv);

            emptyHint = new Label();
            emptyHint.Text = "\u8fd8\u6ca1\u6709\u7559\u5e95\uff1a\u6539\u4e00\u6b21\u5217\u8868" +
                             "\uff08\u6dfb\u52a0\u3001\u7f16\u8f91\u6216\u5220\u9664\uff09\u5c31\u4f1a\u6709\u3002";
            emptyHint.TextAlign = ContentAlignment.MiddleCenter;
            emptyHint.ForeColor = Color.FromArgb(154, 161, 168);
            emptyHint.SetBounds(18, 40, 704, 296);
            emptyHint.Visible = false;
            Controls.Add(emptyHint);

            Button use = MainForm.Flat("\u7528\u9009\u4e2d\u7684\u7559\u5e95", 150,
                Color.FromArgb(0, 122, 204), Color.White);
            use.SetBounds(16, 378, 150, 32);
            use.Click += new EventHandler(OnUse);
            Controls.Add(use);

            Button file = MainForm.Flat("\u4ece\u5907\u4efd\u6587\u4ef6\u2026", 150,
                Color.White, Color.FromArgb(35, 40, 45));
            file.SetBounds(174, 378, 150, 32);
            file.Click += new EventHandler(OnFile);
            Controls.Add(file);

            Button cancel = MainForm.Flat("\u53d6\u6d88", 96, Color.FromArgb(240, 242, 245), Color.FromArgb(40, 45, 50));
            cancel.SetBounds(628, 378, 96, 32);
            cancel.DialogResult = DialogResult.Cancel;
            Controls.Add(cancel);

            AcceptButton = use;
            CancelButton = cancel;
            Fill();
        }

        private void Fill()
        {
            lv.BeginUpdate();
            lv.Items.Clear();
            string[] all = SrvFile.BackupsNewestFirst();
            for (int i = 0; i < all.Length; i++)
            {
                int n = -1;
                try { n = SrvFile.CountOf(File.ReadAllText(all[i], Encoding.UTF8)); }
                catch (Exception) { }
                ListViewItem it = new ListViewItem(Pretty(all[i]));
                it.SubItems.Add(n < 0 ? "?" : n.ToString());
                it.SubItems.Add(Path.GetFileName(all[i]));
                it.Tag = all[i];
                lv.Items.Add(it);
            }
            lv.EndUpdate();
            emptyHint.Visible = (lv.Items.Count == 0);
            lv.Visible = (lv.Items.Count > 0);
        }

        // servers-20261121-201537.dat -> 2026-11-21 20:15:37
        private static string Pretty(string path)
        {
            string n = Path.GetFileNameWithoutExtension(path);
            int a = n.IndexOf('-');
            if (a < 0 || n.Length < a + 16) { return n; }
            string d = n.Substring(a + 1, 8);
            string t = n.Substring(a + 10);
            return d.Substring(0, 4) + "-" + d.Substring(4, 2) + "-" + d.Substring(6, 2) +
                   " " + t.Substring(0, 2) + ":" + t.Substring(2, 2) + ":" + t.Substring(4, 2);
        }

        private void OnUse(object sender, EventArgs e)
        {
            if (lv.SelectedItems.Count == 0)
            {
                Warn("\u5148\u5728\u540d\u5355\u91cc\u9009\u4e2d\u4e00\u4efd\u7559\u5e95");
                return;
            }
            string path = (string)lv.SelectedItems[0].Tag;
            List<Srv> next;
            try { next = SrvFile.Parse(File.ReadAllText(path, Encoding.UTF8)); }
            catch (Exception ex) { Warn("\u8bfb\u4e0d\u4e86\u8fd9\u4e2a\u6587\u4ef6\uff1a" + ex.Message); return; }
            Apply(next, Path.GetFileName(path));
        }

        private void OnFile(object sender, EventArgs e)
        {
            OpenFileDialog d = new OpenFileDialog();
            d.Title = Text;
            d.CheckFileExists = true;
            d.Filter = "\u5907\u4efd\u6587\u4ef6 (*.rdpadmin-backup)|*.rdpadmin-backup|" +
                       "\u6240\u6709\u6587\u4ef6 (*.*)|*.*";
            if (d.ShowDialog(this) != DialogResult.OK) { return; }
            PassForm p = new PassForm();
            if (p.ShowDialog(this) != DialogResult.OK) { return; }
            string err;
            List<Srv> next = BackupPack.Open(d.FileName, p.Value, out err);
            p.Wipe();
            if (next == null) { Warn(err); return; }
            Apply(next, Path.GetFileName(d.FileName));
        }

        // Both paths land here. Nothing moves before the confirmation; if the write
        // fails the in-memory copy goes back, so the screen and the disk stay one version.
        private void Apply(List<Srv> next, string src)
        {
            if (next == null || next.Count == 0)
            {
                Warn("\u8fd9\u4efd\u91cc\u4e00\u53f0\u90fd\u6ca1\u6709\uff0c\u6062\u590d\u5b83\u7b49\u4e8e\u6e05\u7a7a\u5217\u8868");
                return;
            }
            string prev = SrvFile.Serialize(false);
            string q = "\u5f53\u524d " + SrvFile.All().Count.ToString() +
                       " \u53f0\u5c06\u88ab\u66ff\u6362\u6210\u8fd9\u4efd\u91cc\u7684 " + next.Count.ToString() +
                       " \u53f0\u3002\r\n\r\n\u73b0\u5728\u8fd9\u4efd\u4f1a\u5148\u81ea\u52a8\u7559\u5e95\uff0c" +
                       "\u66ff\u6362\u4ee5\u540e\u8fd8\u80fd\u6362\u56de\u6765\u3002";
            if (MessageBox.Show(this, q, Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes) { return; }
            SrvFile.SetList(next);
            if (!SrvFile.Save())
            {
                SrvFile.SetList(SrvFile.Parse(prev));
                Warn(SrvFile.LastError());
                return;
            }
            Did = true;
            From = src;
            Count = next.Count;
            DialogResult = DialogResult.OK;
        }

        private void Warn(string text)
        {
            MessageBox.Show(this, text, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    // ------------------------------------------------------------ one passphrase box
    internal class PassForm : Form
    {
        public string Value = "";
        private TextBox t;

        public PassForm()
        {
            Text = "\u53e3\u4ee4";
            ClientSize = new Size(460, 152);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            Font = MainForm.UiFont();
            BackColor = Color.White;

            Label l = new Label();
            l.Text = "\u8fd9\u4efd\u5907\u4efd\u7684\u53e3\u4ee4\uff1a";
            l.SetBounds(24, 16, 410, 20);
            Controls.Add(l);

            t = new TextBox();
            t.UseSystemPasswordChar = true;
            t.SetBounds(24, 40, 410, 24);
            Controls.Add(t);

            Button ok = MainForm.Flat("\u89e3\u5bc6", 96, Color.FromArgb(0, 122, 204), Color.White);
            ok.SetBounds(338, 106, 96, 32);
            ok.Click += new EventHandler(OnOk);
            Controls.Add(ok);

            Button cancel = MainForm.Flat("\u53d6\u6d88", 96, Color.FromArgb(240, 242, 245), Color.FromArgb(40, 45, 50));
            cancel.SetBounds(234, 106, 96, 32);
            cancel.DialogResult = DialogResult.Cancel;
            Controls.Add(cancel);

            AcceptButton = ok;
            CancelButton = cancel;
            Shown += new EventHandler(OnFocus);
        }

        private void OnFocus(object sender, EventArgs e) { t.Focus(); }

        private void OnOk(object sender, EventArgs e)
        {
            Value = t.Text;
            DialogResult = DialogResult.OK;
        }

        // Wipe the box after decrypting: a passphrase should live one keystroke, not a copy.
        public void Wipe() { t.Clear(); Value = ""; }
    }

    // ------------------------------------------------------------ main window
    internal class MainForm : Form
    {
        private ListView list;
        private Panel card;
        private Label summary;
        private Label emptyHint;
        private Label dot;
        private Label status;
        private Button btnConnect;
        private Button btnKnock;
        private Button btnAdd;
        private Button btnEdit;
        private Button btnDel;
        private Button btnAdmin;
        private Button btnBak;
        private Button btnRes;
        private bool adminNext;
        private bool busy;
        private Srv pending;
        private bool pendingLaunch;

        private delegate void KnockDone(Srv s, string err);

        private static Font uiFont;
        private static Font titleFont;
        private static Font listFont;

        public static Font UiFont()
        {
            if (uiFont != null) { return uiFont; }
            try { uiFont = new Font("Microsoft YaHei UI", 9F); }
            catch (Exception) { uiFont = SystemFonts.MessageBoxFont; }
            return uiFont;
        }

        // One button factory for the whole app. Flat buttons have no hover of
        // their own, so the colour they came in with is swapped for a slightly
        // lighter or darker one while the pointer is over them: that is the
        // cheapest way to make a WinForms window feel alive.
        public static Button Flat(string text, int w, Color back, Color fore)
        {
            Button b = new Button();
            b.Text = text;
            b.Width = w;
            b.Height = 32;
            b.FlatStyle = FlatStyle.Flat;
            b.FlatAppearance.BorderSize = back == Color.White || IsLight(back) ? 1 : 0;
            b.FlatAppearance.BorderColor = Color.FromArgb(206, 212, 218);
            b.BackColor = back;
            b.ForeColor = fore;
            b.Cursor = Cursors.Hand;
            b.Font = UiFont();
            b.UseVisualStyleBackColor = false;
            b.Tag = new Color[] { back, HoverOf(back) };
            b.MouseEnter += new EventHandler(OnHoverIn);
            b.MouseLeave += new EventHandler(OnHoverOut);
            return b;
        }

        private static bool IsLight(Color c)
        {
            int lum = (c.R * 299 + c.G * 587 + c.B * 114) / 1000;
            return lum > 170;
        }

        private static Color HoverOf(Color c)
        {
            if (IsLight(c))
            {
                return Color.FromArgb(Math.Max(0, c.R - 16), Math.Max(0, c.G - 16), Math.Max(0, c.B - 14));
            }
            return Color.FromArgb(Math.Min(255, c.R + 24), Math.Min(255, c.G + 24), Math.Min(255, c.B + 30));
        }

        private static void OnHoverIn(object sender, EventArgs e)
        {
            Button b = sender as Button;
            if (b == null || !b.Enabled) { return; }
            Color[] pair = b.Tag as Color[];
            if (pair == null || pair.Length != 2) { return; }
            b.BackColor = pair[1];
        }

        private static void OnHoverOut(object sender, EventArgs e)
        {
            Button b = sender as Button;
            if (b == null) { return; }
            Color[] pair = b.Tag as Color[];
            if (pair == null || pair.Length != 2) { return; }
            b.BackColor = pair[0];
        }

        public MainForm()
        {
            Text = "\u8fdc\u7a0b\u670d\u52a1\u5668\u7ba1\u7406";
            ClientSize = new Size(960, 660);
            MinimumSize = new Size(820, 520);
            StartPosition = FormStartPosition.CenterScreen;
            Font = UiFont();
            BackColor = Color.FromArgb(244, 246, 249);
            // csc /win32icon only stamps the PE image; a Form does not read it
            // back, so without this the title bar shows the generic icon.
            try { Icon = System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch (Exception) { }
            Build();
            RefreshList();
            if (SrvFile.All().Count == 0)
            {
                Say("\u8fd8\u6ca1\u6709\u670d\u52a1\u5668\u3002\u70b9\u300e\u6dfb\u52a0\u300f\u628a\u90a3\u53f0\u7684\u5730\u5740\u548c\u6572\u95e8 URL \u586b\u8fdb\u6765\uff0c\u4ee5\u540e\u4e00\u6b65\u5c31\u662f\u8fde\u63a5\u3002", false);
            }
            else if (SrvFile.LastError().Length != 0)
            {
                Say(SrvFile.LastError(), true);
            }
        }

        private void Build()
        {
            Label head = new Label();
            head.Text = "\u8fdc\u7a0b\u670d\u52a1\u5668";
            head.Font = TitleFont();
            head.ForeColor = Color.FromArgb(26, 31, 36);
            head.SetBounds(24, 16, 320, 32);
            Controls.Add(head);

            summary = new Label();
            summary.TextAlign = ContentAlignment.MiddleRight;
            summary.ForeColor = Color.FromArgb(138, 145, 153);
            summary.SetBounds(600, 22, 336, 22);
            summary.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            summary.Text = "";
            Controls.Add(summary);

            Label sub = new Label();
            sub.Text = "\u9009\u4e00\u53f0\u70b9\u300e\u8fde\u63a5\u300f\uff1b\u5f53\u5929\u7b2c\u4e00\u6b21\u8fde\u63a5\u4f1a\u5148\u81ea\u52a8\u6572\u95e8\uff0c\u4e4b\u540e\u4ea4\u7ed9\u8fdc\u7a0b\u684c\u9762\u3002";
            sub.ForeColor = Color.FromArgb(107, 114, 128);
            sub.SetBounds(24, 50, 720, 22);
            Controls.Add(sub);

            card = new Panel();
            card.BackColor = Color.White;
            card.SetBounds(16, 84, 928, 486);
            card.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            card.Paint += new PaintEventHandler(OnCardPaint);
            Controls.Add(card);

            list = new ListView();
            list.View = View.Details;
            list.FullRowSelect = true;
            list.MultiSelect = false;
            list.HideSelection = false;
            list.GridLines = false;
            list.BorderStyle = BorderStyle.None;
            list.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            list.Font = ListFont();
            list.BackColor = Color.White;
            list.SetBounds(10, 10, 908, 466);
            list.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            list.Columns.Add("\u540d\u79f0", 150, HorizontalAlignment.Left);
            list.Columns.Add("\u5730\u5740", 150, HorizontalAlignment.Left);
            list.Columns.Add("\u7aef\u53e3", 70, HorizontalAlignment.Left);
            list.Columns.Add("\u4f1a\u8bdd", 60, HorizontalAlignment.Left);
            list.Columns.Add("\u8d26\u6237", 130, HorizontalAlignment.Left);
            list.Columns.Add("\u6572\u95e8", 260, HorizontalAlignment.Left);
            list.Columns.Add("\u4eca\u5929", 80, HorizontalAlignment.Left);
            list.DoubleClick += new EventHandler(OnListDouble);
            list.KeyDown += new KeyEventHandler(OnListKey);
            list.SelectedIndexChanged += new EventHandler(OnSelChange);
            card.Controls.Add(list);

            emptyHint = new Label();
            emptyHint.Text = "\u8fd8\u6ca1\u6709\u670d\u52a1\u5668\r\n\u70b9\u300e\u6dfb\u52a0\u300f\u586b\u4e0a\u5730\u5740\u548c\u6572\u95e8 URL\uff0c\u4ee5\u540e\u4e00\u6b65\u5c31\u662f\u8fde\u63a5";
            emptyHint.TextAlign = ContentAlignment.MiddleCenter;
            emptyHint.ForeColor = Color.FromArgb(154, 161, 168);
            emptyHint.BackColor = Color.White;
            emptyHint.SetBounds(10, 10, 908, 466);
            emptyHint.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            emptyHint.Visible = false;
            card.Controls.Add(emptyHint);

            btnConnect = Flat("\u8fde\u63a5", 124, Color.FromArgb(15, 108, 189), Color.White);
            btnConnect.SetBounds(16, 584, 124, 38);
            btnConnect.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            btnConnect.Font = new Font(UiFont().FontFamily, 10F, FontStyle.Bold);
            btnConnect.Click += new EventHandler(OnConnect);
            Controls.Add(btnConnect);

            btnKnock = Flat("\u91cd\u65b0\u6572\u95e8", 116, Color.White, Color.FromArgb(35, 40, 45));
            btnKnock.SetBounds(150, 584, 116, 38);
            btnKnock.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            btnKnock.Click += new EventHandler(OnKnockOnly);
            Controls.Add(btnKnock);

            btnAdd = Flat("\u6dfb\u52a0", 88, Color.White, Color.FromArgb(35, 40, 45));
            btnAdd.SetBounds(284, 584, 88, 38);
            btnAdd.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            btnAdd.Click += new EventHandler(OnAdd);
            Controls.Add(btnAdd);

            btnEdit = Flat("\u7f16\u8f91", 88, Color.White, Color.FromArgb(35, 40, 45));
            btnEdit.SetBounds(380, 584, 88, 38);
            btnEdit.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            btnEdit.Click += new EventHandler(OnEdit);
            Controls.Add(btnEdit);

            btnDel = Flat("\u5220\u9664", 88, Color.White, Color.FromArgb(35, 40, 45));
            btnDel.SetBounds(476, 584, 88, 38);
            btnDel.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            btnDel.Click += new EventHandler(OnDelete);
            Controls.Add(btnDel);

            btnAdmin = Flat("\u7ba1\u7406\u8fde\u63a5", 116, Color.White, Color.FromArgb(35, 40, 45));
            btnAdmin.SetBounds(572, 584, 116, 38);
            btnAdmin.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            btnAdmin.Click += new EventHandler(OnConnectAdmin);
            Controls.Add(btnAdmin);

            btnBak = Flat("\u5907\u4efd", 88, Color.White, Color.FromArgb(35, 40, 45));
            btnBak.SetBounds(700, 584, 88, 38);
            btnBak.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            btnBak.Click += new EventHandler(OnBackup);
            Controls.Add(btnBak);

            btnRes = Flat("\u6062\u590d", 88, Color.White, Color.FromArgb(35, 40, 45));
            btnRes.SetBounds(796, 584, 88, 38);
            btnRes.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            btnRes.Click += new EventHandler(OnRestore);
            Controls.Add(btnRes);

            dot = new Label();
            dot.Text = "\u25CF";
            dot.ForeColor = Color.FromArgb(150, 155, 160);
            dot.SetBounds(16, 636, 14, 18);
            dot.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            Controls.Add(dot);

            status = new Label();
            status.SetBounds(34, 636, 910, 18);
            status.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            status.ForeColor = Color.FromArgb(96, 103, 110);
            status.Text = "";
            Controls.Add(status);
        }

        private static Font TitleFont()
        {
            if (titleFont != null) { return titleFont; }
            titleFont = new Font(UiFont().FontFamily, 15F, FontStyle.Bold);
            return titleFont;
        }

        private static Font ListFont()
        {
            if (listFont != null) { return listFont; }
            listFont = new Font(UiFont().FontFamily, 10F);
            return listFont;
        }

        private void OnCardPaint(object sender, PaintEventArgs e)
        {
            Panel p = sender as Panel;
            if (p == null) { return; }
            ControlPaint.DrawBorder(e.Graphics, p.ClientRectangle,
                Color.FromArgb(223, 228, 234), 1, ButtonBorderStyle.Solid,
                Color.FromArgb(223, 228, 234), 1, ButtonBorderStyle.Solid,
                Color.FromArgb(223, 228, 234), 1, ButtonBorderStyle.Solid,
                Color.FromArgb(223, 228, 234), 1, ButtonBorderStyle.Solid);
        }

        // ---------------------------------------------------------- list glue
        private void RefreshList()
        {
            int idx = list.SelectedIndices.Count > 0 ? list.SelectedIndices[0] : -1;
            list.BeginUpdate();
            list.Items.Clear();
            List<Srv> all = SrvFile.All();
            int knocked = 0;
            for (int i = 0; i < all.Count; i++)
            {
                Srv s = all[i];
                ListViewItem it = new ListViewItem(s.name);
                it.SubItems.Add(s.host);
                it.SubItems.Add(s.port.ToString());
                it.SubItems.Add(s.admin ? "\u7ba1\u7406" : "\u666e\u901a");
                it.SubItems.Add(s.user);
                it.SubItems.Add(MaskKnock(s.knock));
                it.SubItems.Add(s.KnockedToday() ? "\u5df2\u6572" : "\u672a\u6572");
                if (s.KnockedToday()) { knocked++; }
                it.Tag = s;
                list.Items.Add(it);
            }
            if (idx >= 0 && idx < list.Items.Count) { list.Items[idx].Selected = true; }
            else if (list.Items.Count > 0) { list.Items[0].Selected = true; }
            list.EndUpdate();

            emptyHint.Visible = (list.Items.Count == 0);
            list.Visible = (list.Items.Count > 0);
            summary.Text = all.Count == 0
                ? ""
                : "\u5171 " + all.Count.ToString() + " \u53f0 \u00b7 \u4eca\u5929\u5df2\u6572 " + knocked.ToString() + " \u53f0";
            if (list.Items.Count > 0) { list.Focus(); }
        }

        private static string MaskKnock(string url)
        {
            if (url == null || url.Length == 0) { return "\uff08\u6ca1\u586b\uff09"; }
            int slash = url.LastIndexOf('/');
            if (slash < 0 || slash + 1 >= url.Length) { return url; }
            string tail = url.Substring(slash + 1);
            if (tail.Length <= 6) { return url; }
            return url.Substring(0, slash + 1) + tail.Substring(0, 4) + "********";
        }

        private Srv Selected()
        {
            if (list.SelectedItems.Count == 0) { return null; }
            return (Srv)list.SelectedItems[0].Tag;
        }

        private void OnSelChange(object sender, EventArgs e)
        {
            Srv s = Selected();
            if (s == null) { return; }
            if (busy) { return; }
            if (s.KnockedToday()) { Say(s.name + "\uff1a" + s.Addr() + "\uff0c\u4eca\u5929\u5df2\u7ecf\u6572\u8fc7\u95e8\uff0c\u53ef\u4ee5\u76f4\u63a5\u8fde", false); }
            else { Say(s.name + "\uff1a" + s.Addr() + "\uff0c\u4eca\u5929\u8fd8\u6ca1\u6572\uff0c\u70b9\u300e\u8fde\u63a5\u300f\u4f1a\u5148\u6572\u95e8", false); }
        }

        private void OnListDouble(object sender, EventArgs e)
        {
            OnConnect(null, null);
        }

        private void OnListKey(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter) { OnConnect(null, null); e.Handled = true; }
        }

        // ---------------------------------------------------------- actions
        private void OnConnect(object sender, EventArgs e)
        {
            if (busy) { return; }
            Srv s = Selected();
            if (s == null) { Say("\u5148\u5728\u4e0a\u9762\u9009\u4e2d\u4e00\u53f0\u670d\u52a1\u5668", true); return; }
            adminNext = s.admin;
            if (s.KnockedToday())
            {
                LaunchIt(s);
                return;
            }
            StartKnock(s, true);
        }

        // Same door, same credential, different session: /admin reaches the
        // console session, which is the only one some 2008 R2 jobs allow.
        private void OnConnectAdmin(object sender, EventArgs e)
        {
            if (busy) { return; }
            Srv s = Selected();
            if (s == null) { Say("\u5148\u5728\u4e0a\u9762\u9009\u4e2d\u4e00\u53f0\u670d\u52a1\u5668", true); return; }
            adminNext = true;
            if (s.KnockedToday())
            {
                LaunchIt(s);
                return;
            }
            StartKnock(s, true);
        }

        private void OnKnockOnly(object sender, EventArgs e)
        {
            if (busy) { return; }
            Srv s = Selected();
            if (s == null) { Say("\u5148\u5728\u4e0a\u9762\u9009\u4e2d\u4e00\u53f0\u670d\u52a1\u5668", true); return; }
            StartKnock(s, false);
        }

        private void OnAdd(object sender, EventArgs e)
        {
            if (busy) { return; }
            EditForm f = new EditForm(null);
            if (f.ShowDialog(this) != DialogResult.OK) { return; }
            SrvFile.All().Add(f.Result);
            bool ok = SrvFile.Save();
            RefreshList();
            if (list.Items.Count > 0) { list.Items[list.Items.Count - 1].Selected = true; }
            if (!ok) { Say(SrvFile.LastError(), true); return; }
            AfterSave("\u5df2\u6dfb\u52a0 " + f.Result.name);
        }

        private void OnEdit(object sender, EventArgs e)
        {
            if (busy) { return; }
            Srv s = Selected();
            if (s == null) { Say("\u5148\u9009\u4e2d\u4e00\u53f0\u518d\u70b9\u300e\u7f16\u8f91\u300f", true); return; }
            EditForm f = new EditForm(s);
            if (f.ShowDialog(this) != DialogResult.OK) { return; }
            int idx = list.SelectedIndices.Count > 0 ? list.SelectedIndices[0] : 0;
            List<Srv> all = SrvFile.All();
            Srv keep = all[idx];
            f.Result.daily = keep.daily;
            if (f.Result.host != keep.host || f.Result.port != keep.port) { Cred.Forget(keep); }
            all[idx] = f.Result;
            bool ok = SrvFile.Save();
            RefreshList();
            if (!ok) { Say(SrvFile.LastError(), true); return; }
            AfterSave("\u5df2\u4fdd\u5b58 " + f.Result.name);
        }

        private void OnDelete(object sender, EventArgs e)
        {
            if (busy) { return; }
            Srv s = Selected();
            if (s == null) { Say("\u5148\u9009\u4e2d\u4e00\u53f0\u518d\u70b9\u300e\u5220\u9664\u300f", true); return; }
            DialogResult r = MessageBox.Show(this,
                "\u5220\u9664\u300e" + s.name + "\u300f\uff1f\u53ea\u662f\u4ece\u8fd9\u53f0\u7535\u8111\u7684\u5217\u8868\u91cc\u53bb\u6389\uff0c\u670d\u52a1\u5668\u90a3\u8fb9\u4e0d\u53d7\u5f71\u54cd\u3002",
                "\u5220\u9664\u670d\u52a1\u5668", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2);
            if (r != DialogResult.Yes) { return; }
            int idx = list.SelectedIndices.Count > 0 ? list.SelectedIndices[0] : 0;
            List<Srv> all = SrvFile.All();
            if (idx >= 0 && idx < all.Count) { all.RemoveAt(idx); }
            Cred.Forget(s);
            bool ok = SrvFile.Save();
            RefreshList();
            if (!ok) { Say(SrvFile.LastError(), true); return; }
            AfterSave("\u5df2\u5220\u9664 " + s.name);
        }

        // ---------------------------------------------------------- backup / restore
        // An export writes nothing and changes nothing, so it takes no backup slot and
        // never adds an identical row to the restore list because he clicked the button.
        private void OnBackup(object sender, EventArgs e)
        {
            if (busy) { return; }
            int n = SrvFile.All().Count;
            if (n == 0)
            {
                Say("\u5217\u8868\u91cc\u8fd8\u6ca1\u6709\u4e00\u53f0\uff0c\u6ca1\u6709\u53ef\u4ee5\u5bfc\u51fa\u7684", true);
                return;
            }
            BackupForm f = new BackupForm(n);
            if (f.ShowDialog(this) != DialogResult.OK) { return; }
            // Copy the dialog's fields into locals first: Form derives from
            // MarshalByRefObject, so calling members straight off its fields is CS1690.
            int done = f.Count;
            string wrote = Path.GetFileName(f.OutPath);
            Say("\u5df2\u5bfc\u51fa " + done.ToString() + " \u53f0\uff08" + wrote + "\uff09", false);
        }

        private void OnRestore(object sender, EventArgs e)
        {
            if (busy) { return; }
            RestoreForm f = new RestoreForm();
            if (f.ShowDialog(this) != DialogResult.OK) { return; }
            int back = f.Count;
            string src = f.From;
            RefreshList();
            AfterSave("\u5df2\u6062\u590d\u6210 " + back.ToString() + " \u53f0\uff08" + src + "\uff09");
        }

        // ---------------------------------------------------------- knock thread
        private void StartKnock(Srv s, bool thenLaunch)
        {
            pending = s;
            pendingLaunch = thenLaunch;
            busy = true;
            EnableButtons(false);
            Say("\u6b63\u5728\u6572\u95e8 " + MaskKnock(s.knock) + " \u2026", false);
            Thread t = new Thread(new ThreadStart(KnockThread));
            t.IsBackground = true;
            t.Start();
        }

        private void KnockThread()
        {
            Srv s = pending;
            string err = Knock.Hit(s);
            try
            {
                BeginInvoke(new KnockDone(OnKnockDone), new object[] { s, err });
            }
            catch (Exception) { }
        }

        private void OnKnockDone(Srv s, string err)
        {
            busy = false;
            EnableButtons(true);
            if (err.Length != 0)
            {
                Say("\u6572\u95e8\u5931\u8d25\uff0c\u6ca1\u6709\u8fde\u63a5\uff1a" + err, true);
                MessageBox.Show(this, "\u6572\u95e8\u5931\u8d25\uff0c\u6ca1\u6709\u8fde\u63a5\u3002\r\n\r\n" + err,
                    "\u6572\u95e8\u5931\u8d25", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            s.daily = Srv.Today();
            bool ok = SrvFile.Save();
            RefreshList();
            if (!ok) { Say(SrvFile.LastError(), true); return; }
            AfterSave("\u95e8\u5f00\u4e86\uff0c" + s.name + " \u4eca\u5929\u4e0d\u518d\u91cd\u590d\u6572");
            if (pendingLaunch) { LaunchIt(s); }
        }

        private void LaunchIt(Srv s)
        {
            string note = "";
            string err = Launch.Go(s, adminNext, out note);
            if (err.Length != 0)
            {
                Say(err, true);
                MessageBox.Show(this, err, "\u8fde\u63a5\u5931\u8d25", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string what = adminNext ? "\u5df2\u6253\u5f00\u7ba1\u7406\u4f1a\u8bdd" : "\u5df2\u6253\u5f00\u8fdc\u7a0b\u684c\u9762";
            if (note.Length != 0) { Say(what + "\uff0c\u4f46" + note, true); }
            else { Say(what + "\uff1a" + s.name + "\uff08" + s.Addr() + "\uff09", false); }
        }

        private void EnableButtons(bool on)
        {
            btnConnect.Enabled = on;
            btnKnock.Enabled = on;
            btnAdd.Enabled = on;
            btnEdit.Enabled = on;
            btnDel.Enabled = on;
            btnAdmin.Enabled = on;
            btnBak.Enabled = on;
            btnRes.Enabled = on;
        }

        private void Say(string text, bool bad)
        {
            status.Text = text;
            if (bad)
            {
                status.ForeColor = Color.FromArgb(180, 60, 50);
                dot.ForeColor = Color.FromArgb(196, 66, 54);
            }
            else
            {
                status.ForeColor = Color.FromArgb(46, 125, 86);
                dot.ForeColor = Color.FromArgb(52, 158, 96);
            }
        }

        // After a save, one line: whether it wrote, and whether that version is in
        // backups\. A failed backup is not a failed save, but it must be seen - else the
        // restore list is short one row and nobody knows it is the row he wants.
        private void AfterSave(string okMsg)
        {
            string note = SrvFile.BackupNote();
            if (note.Length != 0) { Say(note, true); return; }
            Say(okMsg, false);
        }
    }

    // ------------------------------------------------------------ desktop shortcut
    // This client is meant to be double-clicked, so it keeps a shortcut on the
    // desktop: started from anywhere else and no shortcut there yet - make one.
    // WScript.Shell through late binding, so no interop assembly to ship and
    // no dependency on anybody scripting the shell by hand.
    internal static class Shortcut
    {
        private const string LinkName = "RdpAdmin.lnk";

        public static void Ensure(string exe)
        {
            try
            {
                string dir = Path.GetDirectoryName(exe);
                string[] desks = DesktopFolders();
                for (int i = 0; i < desks.Length; i++)
                {
                    string desk = desks[i];
                    if (desk == null || desk.Length == 0) { continue; }
                    // Already living on the desktop: a shortcut to itself is noise.
                    if (string.Equals(dir, desk, StringComparison.OrdinalIgnoreCase)) { return; }
                    string lnk = Path.Combine(desk, LinkName);
                    // "The file exists" is not "the shortcut works". A link left
                    // over from an older build (dist\RdpAdmin-1.1.exe, deleted
                    // since) passed the File.Exists test, so nothing was ever
                    // created again and the dead icon on the desktop is what
                    // "it does not make a shortcut" looked like (2026-11-26).
                    // Judge by the target instead, and rewrite anything not us.
                    if (SameTarget(lnk, exe)) { return; }
                    if (Write(lnk, exe, dir)) { return; }
                }
            }
            catch (Exception) { }
        }

        // The user's own desktop first (this is a per-user tool), all-users as
        // the fallback for a session where that folder is unavailable.
        private static string[] DesktopFolders()
        {
            string user = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            string common = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
            if (user != null && common != null
                && string.Equals(user, common, StringComparison.OrdinalIgnoreCase))
            {
                return new string[] { user };
            }
            return new string[] { user, common };
        }

        private static bool SameTarget(string lnk, string exe)
        {
            if (!File.Exists(lnk)) { return false; }
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null) { return false; }
                object shell = Activator.CreateInstance(shellType);
                object sc = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod,
                    null, shell, new object[] { lnk });
                if (sc == null) { return false; }
                object t = sc.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty, null, sc, null);
                string target = (t == null) ? "" : t.ToString();
                return string.Equals(target, exe, StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception) { return false; }
        }

        private static bool Write(string lnk, string exe, string dir)
        {
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null) { return false; }
                object shell = Activator.CreateInstance(shellType);
                object sc = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod,
                    null, shell, new object[] { lnk });
                if (sc == null) { return false; }
                Type scType = sc.GetType();
                // SetProperty alone: __ComObject rejects SetProperty|PutDispProperty
                // together with an ArgumentException, it wants exactly one of them.
                BindingFlags put = BindingFlags.SetProperty;
                scType.InvokeMember("TargetPath", put, null, sc, new object[] { exe });
                scType.InvokeMember("WorkingDirectory", put, null, sc, new object[] { dir });
                scType.InvokeMember("Description", put, null, sc,
                    new object[] { "\u8fdc\u7a0b\u670d\u52a1\u5668\u7ba1\u7406\uff1a\u9009\u4e00\u53f0\u70b9\u8fde\u63a5\uff0c\u5f53\u5929\u7b2c\u4e00\u6b21\u5148\u81ea\u52aa\u6572\u95e8" });
                scType.InvokeMember("IconLocation", put, null, sc, new object[] { exe + ",0" });
                scType.InvokeMember("Save", BindingFlags.InvokeMethod, null, sc, null);
                return File.Exists(lnk);
            }
            catch (Exception) { return false; }
        }
    }

    // ------------------------------------------------------------ entry point
    internal static class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {
            bool createdNew;
            instanceLock = new Mutex(true, "Local\\RdpAdmin", out createdNew);
            if (!createdNew)
            {
                ActivateExisting();
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            SrvFile.Load();
            Shortcut.Ensure(Application.ExecutablePath);
            Application.Run(new MainForm());
        }

        // ---- one window per session ----------------------------------------
        // A second launch of RdpAdmin brings the running window forward instead
        // of starting a second copy against the same servers.dat.
        private delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumProc proc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern int GetWindowThreadProcessId(IntPtr hwnd, out int pid);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetClassNameW(IntPtr hwnd, StringBuilder text, int max);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hwnd, int cmd);

        [DllImport("user32.dll")]
        private static extern bool IsIconic(IntPtr hwnd);

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hwnd);

        private static Mutex instanceLock;

        private static bool ActivateExisting()
        {
            string own = Path.GetFileNameWithoutExtension(Application.ExecutablePath);
            IntPtr found = IntPtr.Zero;
            for (int attempt = 0; attempt < 20 && found == IntPtr.Zero; attempt++)
            {
                EnumWindows(delegate(IntPtr h, IntPtr l)
                {
                    int pid;
                    GetWindowThreadProcessId(h, out pid);
                    if (pid == 0 || pid == Process.GetCurrentProcess().Id) { return true; }
                    string name;
                    try { name = Process.GetProcessById(pid).ProcessName; }
                    catch (Exception) { return true; }
                    if (string.Compare(name, own, true) != 0) { return true; }
                    StringBuilder cls = new StringBuilder(128);
                    GetClassNameW(h, cls, cls.Capacity);
                    if (cls.ToString().IndexOf("WindowsForms") != 0) { return true; }
                    found = h;
                    return false;
                }, IntPtr.Zero);
                if (found == IntPtr.Zero) { Thread.Sleep(100); }
            }
            if (found == IntPtr.Zero) { return false; }
            if (IsIconic(found)) { ShowWindow(found, 9); }
            ShowWindow(found, 5);
            SetForegroundWindow(found);
            return true;
        }
    }
}
