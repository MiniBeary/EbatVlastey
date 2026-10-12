using EbatVlastey.Core;
using System.Security.Principal;
using System.Text.Json;

namespace EbatVlastey.App;
static class Program {
    [STAThread]
    static int Main(string[] args) {
        if(args.Contains("--self-test")) {
            try {
                using var bundle=CertificateFactory.Generate(); ConstraintVerifier.Verify(bundle,DateTimeOffset.UtcNow,false);
                var result=new {ok=true,version="0.1.3",mode="read-only",os=Environment.OSVersion.VersionString,cases=bundle.Probes.Length};
                var json=JsonSerializer.Serialize(result); Console.WriteLine(json);
                var report=Array.IndexOf(args,"--report"); if(report>=0 && report+1<args.Length) File.WriteAllText(args[report+1],json);
                return 0;
            } catch(Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }
        }
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm(args.Contains("--ui-smoke")));
        return 0;
    }
}

sealed class MainForm : Form {
    readonly string backupPath=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"EbatVlastey");
    readonly Label state=new(){AutoSize=true};
    readonly TextBox log=new(){Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Dock=DockStyle.Fill};
    readonly List<Button> actions=[];
    readonly TrustService service;
    bool busy;
    public MainForm(bool smoke) {
        Text="EbatVlastey 0.1.3 — предварительная версия"; ClientSize=new Size(780,510); MinimumSize=new Size(690,430); StartPosition=FormStartPosition.CenterScreen;
        Font=new Font("Segoe UI",10); Padding=new Padding(18);
        service=new TrustService(new WindowsTrustStores(),backupPath,WindowsIdentity.GetCurrent().User?.Value ?? throw new InvalidOperationException("Нет пользователя Windows."));
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=5}; layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.Percent,100)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(new Label{Text="Доверие Минцифры: только .ru, .su и .рф",AutoSize=true,Font=new Font(Font.FontFamily,15,FontStyle.Bold),Margin=new Padding(0,0,0,12)},0,0);
        state.Margin=new Padding(0,0,0,12); layout.Controls.Add(state,0,1);
        var row=new FlowLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,Margin=new Padding(0,0,0,12)};
        Add("Установить",async()=> {
            Append("Сохраняется резервная копия. Windows попросит разрешить корень «EbatVlastey Restricted RU Root …».");
            await Run(()=>service.Install(bundle=>BrowserProbe.Verify(bundle,Append)),"Установка проверена. Перезапустите Chrome и Edge.");
        });
        Add("Проверить",()=>Run(service.Verify,"Цепочки Windows и установленное ограничение проверены. Эта кнопка не запускает проверку браузеров."));
        Add("Восстановить",()=>Run(service.Restore,"Восстановление завершено. Перезапустите Chrome и Edge."));
        Add("Проверить сайты",CheckSites);
        layout.Controls.Add(row,0,2); layout.Controls.Add(log,0,3);
        var bottom=new FlowLayoutPanel{AutoSize=true,Dock=DockStyle.Fill,Margin=new Padding(0,12,0,0)};
        var open=new Button{Text="Открыть резервную копию",AutoSize=true}; open.Click+=(_,_)=> { try { Directory.CreateDirectory(backupPath); System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(backupPath){UseShellExecute=true}); } catch(Exception ex) { Append(ex.Message); } }; bottom.Controls.Add(open);
        bottom.Controls.Add(new Label{Text="Только текущий пользователь. Секретные ключи не сохраняются.",AutoSize=true,Margin=new Padding(10,8,0,0)}); layout.Controls.Add(bottom,0,4); Controls.Add(layout);
        var license=new LinkLabel{Text="Лицензии",AutoSize=true,Margin=new Padding(10,8,0,0)};
        license.LinkClicked+=(_,_)=> {
            var text=new System.Text.StringBuilder(); foreach(var name in new[]{"License.Project","License.BouncyCastle","License.DotNet","License.DotNetNotices"}) {using var stream=typeof(Program).Assembly.GetManifestResourceStream(name); if(stream!=null) {using var reader=new StreamReader(stream); text.AppendLine(reader.ReadToEnd());}}
            using var dialog=new Form{Text="Лицензии",Size=new Size(760,560),StartPosition=FormStartPosition.CenterParent}; dialog.Controls.Add(new TextBox{Text=text.ToString(),Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Both,Dock=DockStyle.Fill}); dialog.ShowDialog(this);
        }; bottom.Controls.Add(license);
        FormClosing+=(_,e)=> { if(busy) { e.Cancel=true; Append("Дождитесь окончания операции. Резервную копию не удаляйте."); } };
        Shown+=async(_,_)=> {
            RefreshState();
            if(smoke) { var timer=new System.Windows.Forms.Timer{Interval=800}; timer.Tick+=(_,_)=> {timer.Stop(); timer.Dispose(); Close();}; timer.Start(); return; }
            if(!Environment.Is64BitOperatingSystem || !OperatingSystem.IsWindowsVersionAtLeast(10)) { foreach(var button in actions) button.Enabled=false; Append("Нужна 64-разрядная Windows 10 или 11."); return; }
            try { if(service.State is "Applying" or "RollingBack" or "Prepared") await Run(service.Recover,"Прерванная операция восстановлена."); } catch(Exception ex) { Append(ex.Message); }
        };
        void Add(string title,Func<Task> action) { var button=new Button{Text=title,AutoSize=true,Margin=new Padding(0,0,8,0)}; button.Click+=async(_,_)=> {try {await action();} catch(Exception ex){Append(ex.Message);}}; actions.Add(button); row.Controls.Add(button); }
    }
    async Task Run(Action action,string success) {
        SetBusy(true);
        try { await Task.Run(action); Append(success); }
        catch(Exception ex) { Append(ex.Message); if(ex is AggregateException aggregate) foreach(var inner in aggregate.InnerExceptions) Append(inner.Message); }
        finally { SetBusy(false); RefreshState(); }
    }
    async Task CheckSites() {
        SetBusy(true);
        try {
            using var http=new HttpClient(){Timeout=TimeSpan.FromSeconds(12)};
            foreach(var url in new[]{"https://online.sberbank.ru/","https://www.gosuslugi.ru/","https://www.gosuslugi.ru/goskey","https://example.com/"}) {
                try { using var response=await http.GetAsync(url,HttpCompletionOption.ResponseHeadersRead); Append($"{url} — HTTPS-соединение установлено, HTTP {(int)response.StatusCode}."); }
                catch(Exception ex) { Append($"{url} — проверка недоступна: {ex.Message}"); }
            }
            Append("Это проверка HTTPS. Вход и подписание документов не проверялись.");
        } finally {SetBusy(false);}
    }
    void Append(string text) { if(IsDisposed) return; if(InvokeRequired) { BeginInvoke(()=>Append(text)); return; } log.AppendText(text+Environment.NewLine); }
    void SetBusy(bool value) {busy=value; foreach(var button in actions) button.Enabled=!value; UseWaitCursor=value;}
    void RefreshState() { try { state.Text="Состояние: "+(service.State switch {"Applied"=>"ограничение установлено","RolledBack"=>"прежнее состояние восстановлено","None"=>"этой программой не установлено",_=>"операция требует восстановления"}); } catch(Exception ex) {state.Text="Состояние: журнал установки недоступен"; Append(ex.Message);} }
}
