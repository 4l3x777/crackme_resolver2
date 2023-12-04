import angr
import claripy
import random
import string
import logging

class CrackmeResolver:

    def __init__(self):
        logging.getLogger('angr').setLevel('CRITICAL')

    def generate_password(self, login: str):
        '''Generate password for login
        Input:
            login: str - login for crackme
        Output:
            pair of login, password
        '''
        login_length = 0x102 # from 0x0043833A (0x102 BYTES + '\0')

        if len(login) >= login_length or len(login) == 0:
            print("[-] Fail \n\t name_length must be > 0x0 and <= 0x102")
            return

        # A-Z_a-z_0-9 true -> other to black symbols list
        black_symbols = [i for i in range(0x30)]
        black_symbols += [i for i in range(0x3a, 0x41, 1)]
        black_symbols += [i for i in range(0x5b, 0x61, 1)]
        black_symbols += [i for i in range(0x7b, 0x100, 1)]
        for char in login.encode('cp1251'):
            if char in black_symbols:
                print("[-] Fail \n\t name contain blocked symbol:", hex(char))
                return

        project = angr.Project('bin\Otus_Crackme_01-31158-5b70e2.exe')
        start_addr = 0x00437E70  # sub_437E70
        avoid_addr = [0x00437ED8] # goto false
        success_addr  = 0x00437ECC # goto true
        initial_state = project.factory.blank_state(addr=start_addr)

        login_address = 0xffff200 # random
        str_login = claripy.BVV(bytearray(login.encode('cp1251'))) # static ascii name from symbols not in black_symbols
        initial_state.memory.store(login_address, str_login) # store login

        password_length = 0x4 # random
        password_address = 0xffff000 # random
        str_password = claripy.BVS(b'password', password_length * 8)
        initial_state.memory.store(password_address, str_password) # store password
        # password constraints
        for i in range(0, password_length):
            numeric_zero = initial_state.memory.load(password_address + i, 1) >= ord('0')
            numeric_nine = initial_state.memory.load(password_address + i, 1) <= ord('9')
            
            symbol_a = initial_state.memory.load(password_address + i, 1) >= ord('a')
            symbol_z = initial_state.memory.load(password_address + i, 1) <= ord('z')
            
            symbol_A = initial_state.memory.load(password_address + i, 1) >= ord('A')
            symbol_Z = initial_state.memory.load(password_address + i, 1) <= ord('Z')
            
            initial_state.add_constraints(
                initial_state.solver.Or(
                initial_state.solver.And(numeric_zero, numeric_nine),
                initial_state.solver.And(symbol_a, symbol_z),
                initial_state.solver.And(symbol_A, symbol_Z)
                )
            )
        
        # cdecl sub_437E70 arguments simulation
        initial_state.stack_push(password_address) # password address
        initial_state.stack_push(login_address) # login address
        initial_state.stack_push(0x0) # stub return address

        simulation = project.factory.simgr(initial_state)
        simulation.explore(find=success_addr, avoid=avoid_addr)

        if simulation.found:
            solution_state = simulation.found[0]
            solution_login = solution_state.solver.eval(str_login, cast_to=bytes)
            solution_password = solution_state.solver.eval(str_password, cast_to=bytes)
            print("[+] Success: \n\tlogin is: '{}' \n\tpassword is: '{}'".format(solution_login.decode('cp1251'), solution_password.decode('cp1251')))
        else: print("[-] Fail \n\t pair not found")

    def generate_pair(self):
        '''Generate pair login and password
        Output:
            generated pair of login, password
        '''

        project = angr.Project('bin\Otus_Crackme_01-31158-5b70e2.exe')
        start_addr = 0x00437E70  # sub_437E70
        avoid_addr = [0x00437ED8] # goto false
        success_addr  = 0x00437ECC # goto true
        initial_state = project.factory.blank_state(addr=start_addr)

        login_length = 0x4 # random
        login_address = 0xffff200 # random      
        str_login = claripy.BVV(bytearray(''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for i in range(login_length)).encode('cp1251'))) # static ascii name from symbols
        initial_state.memory.store(login_address, str_login) # store login

        password_length = 0x5 # random
        password_address = 0xffff000 # random
        str_password = claripy.BVS(b'password', password_length * 8)
        initial_state.memory.store(password_address, str_password) # store password
        # password constraints
        for i in range(0, password_length):
            numeric_zero = initial_state.memory.load(password_address + i, 1) >= ord('0')
            numeric_nine = initial_state.memory.load(password_address + i, 1) <= ord('9')
            
            symbol_a = initial_state.memory.load(password_address + i, 1) >= ord('a')
            symbol_z = initial_state.memory.load(password_address + i, 1) <= ord('z')
            
            symbol_A = initial_state.memory.load(password_address + i, 1) >= ord('A')
            symbol_Z = initial_state.memory.load(password_address + i, 1) <= ord('Z')
            
            initial_state.add_constraints(
                initial_state.solver.Or(
                initial_state.solver.And(numeric_zero, numeric_nine),
                initial_state.solver.And(symbol_a, symbol_z),
                initial_state.solver.And(symbol_A, symbol_Z)
                )
            )
        
        # cdecl sub_437E70 arguments simulation
        initial_state.stack_push(password_address) # password address
        initial_state.stack_push(login_address) # login address
        initial_state.stack_push(0x0) # stub return address

        simulation = project.factory.simgr(initial_state)
        simulation.explore(find=success_addr, avoid=avoid_addr)

        if simulation.found:
            solution_state = simulation.found[0]
            solution_login = solution_state.solver.eval(str_login, cast_to=bytes)
            solution_password = solution_state.solver.eval(str_password, cast_to=bytes)
            print("[+] Success: \n\tlogin is: '{}' \n\tpassword is: '{}'".format(solution_login.decode('cp1251'), solution_password.decode('cp1251')))
        else: print("[-] Fail \n\t pair not found")

if __name__ == "__main__":
    resolver = CrackmeResolver()
    resolver.generate_password("Apple")
    resolver.generate_password("Github")
    resolver.generate_pair()

   