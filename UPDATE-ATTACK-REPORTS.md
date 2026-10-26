# تحديث تقارير الهجمات وMITRE ATT&CK

## الملفات التي تُستبدل

استخرج محتويات الحزمة فوق مجلد المشروع مع السماح باستبدال الملفات. لا تحذف مجلد `capture` أو قاعدة `audit.sqlite` أو مجلد `.venv`.

## تشغيل التحليل والتقرير

افتح PowerShell داخل مجلد المشروع، ثم شغّل:

```powershell
cd C:\Users\A\Desktop\sentinel-app
```

نزّل مرجع MITRE ATT&CK الرسمي مرة واحدة أو عند الرغبة في تحديثه (يتطلب اتصال إنترنت):

```powershell
.\.venv\Scripts\python.exe -m sentinel ctl intel sync-attack --output data/attack/enterprise-attack.json
```

شغّل تحليل ملفات الالتقاط الموجودة:

```powershell
.\.venv\Scripts\python.exe -m sentinel.pilot.runner --config pilot_config.yaml --capture-dir capture --manifest capture/manifest.json --report-dir reports --attack-catalog data/attack/enterprise-attack.json
```

افتح التقرير الناتج:

```powershell
Start-Process .\reports\latest.html
```

لكل تشغيل تقرير HTML وJSON باسم مستقل، بالإضافة إلى `reports\latest.html`.

## إظهار التقرير في لوحة Sentinel

أوقف خادم الواجهة القديم من نافذته باستخدام `Ctrl+C` ثم شغّله مجددًا هكذا:

```powershell
$env:SENTINEL_OPS_UI_TOKEN = "local-only-demo-change-me"
@'
from pathlib import Path
from sentinel.config.loader import load_config
from sentinel.auditstore.store import Store
from sentinel.ui.app import serve

cfg = load_config("pilot_config.yaml")
cfg["ops_ui"]["enabled"] = True
serve(
    cfg,
    store=Store("capture/audit.sqlite", check_same_thread=False),
    capture_dir=Path("capture"),
    report_dir=Path("reports"),
)
'@ | .\.venv\Scripts\python.exe -
```

افتح `http://127.0.0.1:8080/`؛ استخدم إضافة المتصفح التي تضيف ترويسة `X-Sentinel-Token` إلى طلبات العنوان المحلي كما في إعدادك السابق. التقرير متاح أيضًا مباشرة عند وجود الترويسة على `http://127.0.0.1:8080/reports/latest`.

## إثراء CVE اختياري

يبحث هذا الخيار عن CVE فقط عندما يكون معرّف CVE موجودًا داخل دليل الحدث؛ نوع الهجوم وحده لا يكفي لاستنتاج ثغرة. يرسل طلب قراءة إلى NIST NVD:

```powershell
.\.venv\Scripts\python.exe -m sentinel.pilot.runner --config pilot_config.yaml --capture-dir capture --manifest capture/manifest.json --report-dir reports --attack-catalog data/attack/enterprise-attack.json --enrich-vulnerabilities
```

مفتاح NVD اختياري، ويمكن ضبطه في جلسة PowerShell الحالية عبر `$env:NVD_API_KEY = "..."`.

## معنى التصنيف والتعلّم

التصنيف وربط ATT&CK مرشح مبني على إشارات Sentinel؛ التقرير يعرض الدليل ودرجة الثقة، ولا يدّعي تأكيد هوية المهاجم أو التقنية. قاعدة ATT&CK تضيف أوصاف التقنيات وأساليب الكشف والتكتيكات. هذا إثراء معرفي للشرح والتقرير وليس تدريبًا تلقائيًا أو تعديلًا لقواعد القرار. تشغيل Pilot يظل Shadow فقط ولا ينفذ حظرًا أو تغييرات على الشبكة.
