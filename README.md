![](https://raw.githubusercontent.com/shjalayeri/Noroi/master/noroi_logo.png "Noroi Logo")
##### About :
Noroi is a simple "Polymorphic Decoder Generator" using a Hand-written contex-free-grammer. Current version can bypass shellcode emulators by accessing a static windows address between getpc and decoding process (cuase AV in emulator and result to skip without getpc detection). I think libemu is unable to detect this shellcode. 

##### Suported Techniques :
* Register Swaping
* Instruction Substitution
* Random XOR Key
* Random Junk Insertation

##### TODO List :
1. swap regs with XOR/ADD/SUB
2. use CMOV/NOT/NEG/SHR/AND/OR/XOR/XCHG/XADD
3. Indirect branches for anti.disassembly. eg JMP ECX
4. Hiding CFG by self-modifing
5. SSE/FPU decryption routine
6. XOR with MZ of nth module or any other fix data ( read PTR in shellcode detectors 7.31 ~= 19 )
7. Shellcode relocation with native APIs like NtAllocateVirualMemory/NtReadVirtualMemory
8. NO two null-bytes continuously (or no null-byte at all)
9. more realistic FPU/SSE garbages
10. re-arrange the garbage table for every generation
11. x64 support
12. Hiding getpc pattern by runtime decode and execution of getpc (using stack for example) eg:  
    MOV REG, GETPC_INST_CONSTANT  
    XOR REG, RANDOM_VALUE  
    PUSH REG  
    CALL ESP  
    <REST OF CODE>  

##### Test :
I have tested Noroi with SkyLined's dl-loadlib in windows 7 x64 and it was working. current version only works on x86 systems ( not wow64 ), if you want to use it on a x64, remove the linse makred with "this one is for x86 only".  

###### /Shahriyar
