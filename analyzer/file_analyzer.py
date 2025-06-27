import subprocess
import os
import re
from oletools.olevba import VBA_Parser


def analyze_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()

    if ext == '.pdf':
        return analyze_pdf(filepath)
    elif ext in ('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'):
        return analyze_office_doc(filepath)
    elif ext in ('.js', '.ps1', '.bat', '.vbs', '.sh'):
        return analyze_script_file(filepath)
    else:
        return analyze_generic_file(filepath)


def analyze_pdf(filepath):
    try:
        result = subprocess.run(['python3', 'analyzer/pdfid.py', filepath], capture_output=True, text=True)
        output = result.stdout
        lines = output.splitlines()

        summary = {
            '/JavaScript': 0,
            '/JS': 0,
            '/Launch': 0,
            '/OpenAction': 0,
            '/EmbeddedFile': 0,
        }

        detailed_info = {
            '/JavaScript': {
                'desc': 'Embeds JavaScript code in the PDF.',
                'risk': 'Can exploit PDF reader vulnerabilities to run scripts silently.'
            },
            '/JS': {
                'desc': 'Shortcut for embedded JavaScript.',
                'risk': 'Triggers automatic script execution — risky if obfuscated.'
            },
            '/Launch': {
                'desc': 'Executes external applications (like cmd.exe).',
                'risk': 'Can be abused to run malware when PDF is opened.'
            },
            '/OpenAction': {
                'desc': 'Auto-runs an action when the PDF is opened.',
                'risk': 'Common in phishing attacks to silently launch malicious code.'
            },
            '/EmbeddedFile': {
                'desc': 'File is embedded inside the PDF.',
                'risk': 'May contain viruses or hidden executables (e.g., ransomware installers).'
            }
        }

        for line in lines:
            for key in summary:
                if key in line:
                    summary[key] = int(line.strip().split()[-1])

        risk_flags = [key for key, val in summary.items() if val > 0]

        if risk_flags:
            status = "⚠️ Suspicious PDF Indicators Found:\n"
            for flag in risk_flags:
                info = detailed_info[flag]
                status += f"\n🔸 {flag}: {summary[flag]} time(s)\n" \
                          f"   🔍 {info['desc']}\n" \
                          f"   🚨 {info['risk']}\n"
        else:
            status = "✅ PDF appears clean. No suspicious indicators found."

        summary_text = "\nPDF Flag Summary:\n" + "\n".join([f"{key}: {val}" for key, val in summary.items()])
        return f"{status}\n{summary_text}\n\n📄 Full PDFID Output:\n{output}"

    except Exception as e:
        return f"PDF Analysis Failed: {e}"


def analyze_office_doc(filepath):
    try:
        vba_parser = VBA_Parser(filepath)
        if vba_parser.detect_vba_macros():
            report = "⚠️ Suspicious Office Macros Found:\n"
            macro_count = 0
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                macro_count += 1
                preview = vba_code.strip()[:300]
                report += f"\n🔸 Macro {macro_count} from {vba_filename}:\n"
                report += f"   📃 Preview:\n{preview}\n...\n"

            analysis = vba_parser.analyze_macros()
            if analysis:
                report += "\n🔍 Suspicious Indicators:\n"
                for kw_type, keyword, desc in analysis:
                    report += f"   🔸 {keyword} → {desc}\n"

            report += "\n🚨 Macros can execute code on victim's system."
        else:
            report = "✅ No Macros Detected in Office Document."

        return report

    except Exception as e:
        return f"Office Document Analysis Failed: {e}"


def analyze_script_file(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read().lower()

        suspicious_keywords = ["powershell", "cmd.exe", "downloadfile", "base64", "eval", "exec"]
        found = [kw for kw in suspicious_keywords if kw in content]

        if found:
            report = "⚠️ Suspicious Script Indicators Found:\n"
            for kw in found:
                report += f"🔸 {kw}\n"
        else:
            report = "✅ Script appears clean."

        return report

    except Exception as e:
        return f"Script Analysis Failed: {e}"


def analyze_generic_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            content = f.read()

        text = content.decode(errors='ignore').lower()
        indicators = ['cmd.exe', 'powershell', 'wget', 'curl', 'base64', 'createobject', 'launch', 'script']
        found = [i for i in indicators if i in text]
        urls = re.findall(r'https?://[^\s]+', text)

        if found or urls:
            result = "⚠️ Suspicious content detected:\n"
            if found:
                result += "\n🔸 Keywords:\n" + "\n".join(f" - {i}" for i in found)
            if urls:
                result += "\n\n🔗 URLs:\n" + "\n".join(f" - {u}" for u in urls)
        else:
            result = "✅ No obvious indicators found in file."

        return result

    except Exception as e:
        return f"Generic File Analysis Failed: {e}"