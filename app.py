import os
import shutil
import hashlib
import math
import time
import json
from pathlib import Path
import PySimpleGUI as sg

# ---------- Configurações ----------
QUARANTINE_DIR = "quarantine"
SIGNATURES_FILE = "signatures.txt"
SUSPICIOUS_EXTS = {".exe", ".dll", ".scr", ".pif", ".vbs", ".js", ".jar", ".bat", ".cmd", ".msi"}
ENTROPY_THRESHOLD = 7.5  # se >7.5 considera alto (empírico)
LOG_FILE = "scan_report.json"
# ------------------------------------

def ensure_environment():
    Path(QUARANTINE_DIR).mkdir(exist_ok=True)

def load_signatures(path=SIGNATURES_FILE):
    sigs = set()
    if not os.path.exists(path):
        return sigs
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            h = line.strip().lower()
            if h:
                sigs.add(h)
    return sigs

def sha256_of_file(filepath, block_size=65536):
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                h.update(block)
    except Exception as e:
        return None, f"erro leitura: {e}"
    return h.hexdigest(), None

def file_entropy(filepath):
    """Calcula entropia de Shannon do arquivo (0 a 8)."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return 0.0
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def scan_path(path, signatures, on_file_found=None):
    """Percorre recursivamente e retorna lista de resultados."""
    results = []
    start = time.time()
    for root, dirs, files in os.walk(path):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, path)
            ext = Path(name).suffix.lower()
            result = {
                "path": full,
                "rel_path": rel,
                "name": name,
                "sha256": None,
                "sha_error": None,
                "is_known_malware": False,
                "suspicious_ext": ext in SUSPICIOUS_EXTS,
                "entropy": None,
                "entropy_suspicious": False,
                "notes": []
            }

            # calc hash
            h, err = sha256_of_file(full)
            result["sha256"] = h
            result["sha_error"] = err
            if err:
                result["notes"].append(err)

            # check signature
            if h and h.lower() in signatures:
                result["is_known_malware"] = True
                result["notes"].append("assinatura conhecida")

            # entropy
            try:
                ent = file_entropy(full)
                result["entropy"] = round(ent, 3)
                if ent >= ENTROPY_THRESHOLD:
                    result["entropy_suspicious"] = True
                    result["notes"].append(f"entropia alta ({result['entropy']})")
            except Exception as e:
                result["notes"].append(f"erro entropia: {e}")

            # suspicious extension
            if result["suspicious_ext"]:
                result["notes"].append(f"extensão suspeita ({ext})")

            results.append(result)
            if on_file_found:
                on_file_found(result)
    elapsed = time.time() - start
    return results, elapsed

def quarantine_file(filepath, quarantine_dir=QUARANTINE_DIR):
    try:
        Path(quarantine_dir).mkdir(exist_ok=True)
        basename = os.path.basename(filepath)
        dest = os.path.join(quarantine_dir, f"{int(time.time())}_{basename}")
        shutil.move(filepath, dest)
        return True, dest
    except Exception as e:
        return False, str(e)

def save_report(results, scan_root, elapsed, out=LOG_FILE):
    report = {
        "scan_root": scan_root,
        "timestamp": time.time(),
        "elapsed_seconds": elapsed,
        "results": results
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return out

# ---------- GUI ----------
def main():
    ensure_environment()
    sg.theme("DarkBlue3")

    layout = [
        [sg.Text("Antivírus Simples (protótipo) — selecione pasta para escanear")],
        [sg.Input(key="-FOLDER-"), sg.FolderBrowse("Escolher pasta")],
        [sg.Button("Carregar assinaturas"), sg.Text(size=(40,1), key="-SIG-COUNT-")],
        [sg.Button("Escanear"), sg.Button("Quarentenar selecionado"), sg.Button("Abrir quarentena")],
        [sg.Output(size=(100,20))],
        [sg.Text("Resultados (duplo-clique para ver caminho)")],
        [sg.Listbox(values=[], size=(100,10), enable_events=True, key="-RESULTS-")],
        [sg.Button("Exportar relatório JSON"), sg.Button("Gerar .exe (instruções)"), sg.Button("Sair")]
    ]

    window = sg.Window("Antivírus Simples", layout, finalize=True)

    signatures = load_signatures()
    window["-SIG-COUNT-"].update(f"Assinaturas carregadas: {len(signatures)}")

    current_results = []
    scan_root = None

    def print_file_summary(r):
        # função de callback para imprimir progresso
        name = r["rel_path"] if "rel_path" in r else r["path"]
        status = []
        if r.get("is_known_malware"): status.append("MALWARE!")
        if r.get("entropy_suspicious"): status.append("ALTA ENTROPIA")
        if r.get("suspicious_ext"): status.append("EXT SUSPEITA")
        if not status:
            status_text = "OK"
        else:
            status_text = ", ".join(status)
        print(f"[{status_text}] {name}")

    while True:
        event, values = window.read(timeout=100)
        if event == sg.WINDOW_CLOSED or event == "Sair":
            break

        if event == "Carregar assinaturas":
            signatures = load_signatures()
            window["-SIG-COUNT-"].update(f"Assinaturas carregadas: {len(signatures)}")
            print(f"Assinaturas carregadas: {len(signatures)}")

        if event == "Escanear":
            folder = values["-FOLDER-"]
            if not folder or not os.path.isdir(folder):
                sg.popup("Escolha uma pasta válida primeiro.")
                continue
            print(f"Iniciando escaneamento em: {folder}")
            window.refresh()
            current_results, elapsed = scan_path(folder, signatures, on_file_found=print_file_summary)
            print(f"Escaneamento finalizado ({len(current_results)} arquivos) em {elapsed:.1f}s")
            scan_root = folder
            # popular listbox com resumos
            list_values = []
            for i, r in enumerate(current_results):
                label = f"{i+1}. {r['rel_path']} - "
                flags = []
                if r["is_known_malware"]: flags.append("MALWARE")
                if r["entropy_suspicious"]: flags.append("ENTROPIA")
                if r["suspicious_ext"]: flags.append("EXT")
                if flags:
                    label += "[" + ",".join(flags) + "]"
                else:
                    label += "[OK]"
                list_values.append(label)
            window["-RESULTS-"].update(list_values)

        if event == "-RESULTS-":
            # ao selecionar item, exibe o registro detalhado
            sel = values["-RESULTS-"]
            if sel:
                # pega índice pelo prefixo "N. "
                try:
                    first = sel[0]
                    idx = int(first.split(".")[0]) - 1
                    r = current_results[idx]
                    detail = json.dumps(r, indent=2, ensure_ascii=False)
                    sg.popup_scrolled(detail, title="Detalhes do arquivo", size=(80,20))
                except Exception as e:
                    print("Erro ao mostrar detalhes:", e)

        if event == "Quarentenar selecionado":
            sel = values["-RESULTS-"]
            if not sel:
                sg.popup("Selecione um item nos resultados primeiro.")
                continue
            try:
                first = sel[0]
                idx = int(first.split(".")[0]) - 1
                r = current_results[idx]
                path = r["path"]
                ok, info = quarantine_file(path)
                if ok:
                    sg.popup(f"Arquivo movido para quarentena: {info}")
                    print(f"Quarentenado: {path} -> {info}")
                    # atualizar listagem: marca como quarentenado
                    current_results[idx]["notes"].append("quarentenado")
                    list_values[idx] += " [QUARANTENA]"
                    window["-RESULTS-"].update(list_values)
                else:
                    sg.popup("Falha ao quarentenar:", info)
            except Exception as e:
                sg.popup("Erro:", e)

        if event == "Abrir quarentena":
            sg.popup(f"Pasta de quarentena: {os.path.abspath(QUARANTINE_DIR)}")
            try:
                os.startfile(os.path.abspath(QUARANTINE_DIR))
            except Exception:
                pass

        if event == "Exportar relatório JSON":
            if not current_results:
                sg.popup("Nenhum resultado para exportar.")
                continue
            out = save_report(current_results, scan_root or "", elapsed)
            sg.popup(f"Relatório salvo em: {out}")

        if event == "Gerar .exe (instruções)":
            sg.popup_scrolled(
                "Para gerar .exe use PyInstaller. Exemplo:\n\n"
                "1) Instale: pip install pyinstaller\n"
                "2) Rode no terminal (na pasta do projeto):\n\n"
                "   pyinstaller --onefile --windowed app.py --name MeuAntivirus\n\n"
                "Isso cria a pasta 'dist' com 'MeuAntivirus.exe'.\n\n"
                "Obs: executáveis podem exigir permissões de administrador para escanear pastas do sistema."
            )

    window.close()

if __name__ == "__main__":
    main()

