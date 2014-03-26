Noroi, Polymorphic Decoder Generator using a Hand-written CFG
Coded By Shahriyar Jalayeri

Suported Techniques :
    * Register Swaping
    * Instruction Substitution
    * Random XOR Key
    * Random Junk Insertation

Info :
This version currently can bypass shellcode emulators
using accessing a static windows address between getpc
and decoding process (cuase AV in emulator and result 
to skip without getpc detection). current version tested
against libemu and it was unable to detect the shellcode.

Check TODO for further works.

/Shahriyar