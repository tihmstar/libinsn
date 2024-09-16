//
//  insn.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef arm64_insn_hpp
#define arm64_insn_hpp

#include <vector>
#include <stdint.h>

namespace tihmstar{
    namespace libinsn{
        namespace arm64{
            class insn{
            public: //type
                typedef uint64_t loc_t;
                typedef uint64_t offset_t;
                enum type {
                    unknown = 0,
                    /* A */
                    add, adr, adrp, and_, autda, autdza,
                    /* B */
                    b, bcond, bl, blr, blraa, blraaz, blrab, blrabz, br,
                    /* C */
                    cbnz, cbz, ccmp, csel,
                    /* L */
                    ldp, ldr, ldrb, ldrh, ldxr, lsl,
                    /* M */
                    madd, mov, movk, movz, mrs, msr,
                    /* N */
                    nop,
                    /* O */
                    orr,
                    /* P */
                    pacda, pacdza, pacib, pacibsp, pacizb,
                    /* R */
                    ret,
                    /* S */
                    smaddl, stp, str, strb, strh, sub, subs,
                    /* T */
                    tbnz, tbz,
                    /* T */
                    umaddl,

                    /* X */
                    xpacd, xpaci,
                    
                    /* Alias */
                    cmp = subs
                };
                enum subtype{
                    st_general,
                    st_register,
                    st_register_extended,
                    st_immediate,
                    st_literal
                };
                enum supertype{
                    sut_general,
                    sut_branch_imm,
                    sut_memory //load or store
                };
                enum classtype{
                    cl_general,
                    cl_preindex,
                    cl_postindex,
                    cl_offset
                };
                enum cond{
                    EQ = 0b0000,
                    NE = 0b0001,
                    CS = 0b0010,
                    CC = 0b0011,
                    MI = 0b0100,
                    PL = 0b0101,
                    VS = 0b0110,
                    VC = 0b0111,
                    HI = 0b1000,
                    LS = 0b1001,
                    GE = 0b1010,
                    LT = 0b1011,
                    GT = 0b1100,
                    LE = 0b1101,
                    AL = 0b1110
                };
                enum systemreg : uint64_t{
                    currentel   = 0x4212,
                    tpidr_el1   = 0x4684,
                    tpidr_el3   = 0x7684,
                    sctlr_el1   = 0x4080,
                    sctlr_el3   = 0x7080,
                    sp_el0      = 0x4208,
                    sp_el1      = 0x6208,
                    tcr_el1     = 0x4102,
                    tcr_el3     = 0x7102,
                    ttbr0_el1   = 0x4100,
                    ttbr0_el3   = 0x7100,
                    ttbr1_el1   = 0x4101,
                    ttbr1_el3   = 0x7101,
                };
                enum pactype{
                    pac_none = 0,
                    pac_AA,     //BRAA  / BLRAA
                    pac_AAZ,    //BRAAZ / BLRAAZ
                    pac_AB,     //BRAB  / BLRAB
                    pac_ABZ     //BRABZ / BLRAB/
                };
                
                
            private:
                uint32_t _opcode;
                uint64_t _pc;
                type _type;
                
            public:
                insn(uint32_t opcode, uint64_t pc);
                
            public:
                uint32_t opcode();
                uint64_t pc();
                
                constexpr uint8_t insnsize() const {return 4;};

                type type();
                subtype subtype();
                supertype supertype();
                classtype classtype();
                pactype pactype();
                int64_t imm();
                uint8_t ra();
                uint8_t rd();
                uint8_t rn();
                uint8_t rt();
                uint8_t rt2();
                uint8_t rm();
                cond condition();
                uint64_t special();
                
            public: //cast operators
                operator enum type();
                operator loc_t();
                
            static constexpr uint8_t size() {return 4;};
                  
#pragma mark constructor functions
            public: //constructor functions
#pragma mark general
                static insn new_general_adr(loc_t pc, int64_t imm, uint8_t rd);
                static insn new_general_adrp(loc_t pc, int64_t imm, uint8_t rd);
                static insn new_general_br(loc_t pc, uint8_t rn, uint8_t rm = 0, enum pactype pac = pac_none);
                static insn new_general_blr(loc_t pc, uint8_t rn, uint8_t rm = 0, enum pactype pac = pac_none);
                static insn new_general_ldp_index(loc_t pc, int8_t imm, uint8_t rt, uint8_t rt2, uint8_t rn, bool isPreindex = false);
                static insn new_general_ldp_offset(loc_t pc, int8_t imm, uint8_t rt, uint8_t rt2, uint8_t rn);
                static insn new_general_stp_index(loc_t pc, int8_t imm, uint8_t rt, uint8_t rt2, uint8_t rn, bool isPreindex = false);
                static insn new_general_stp_offset(loc_t pc, int8_t imm, uint8_t rt, uint8_t rt2, uint8_t rn);
                static insn new_general_nop(loc_t pc);
                static insn new_general_ret(loc_t pc);
    
#pragma mark register
                static insn new_register_add(loc_t pc, uint8_t imm, uint8_t rn, uint8_t rm, uint8_t rd, bool isSub = false);
                static insn new_register_cmp(loc_t pc, uint8_t imm, uint8_t rn, uint8_t rm, uint8_t rd);
                static insn new_register_ccmp(loc_t pc, cond condition, uint8_t flags, uint8_t rn, uint8_t rm);
                static insn new_register_ldr(loc_t pc, uint8_t rm, uint8_t rn, uint8_t rt, bool isW = false);
                static insn new_register_str(loc_t pc, uint8_t rm, uint8_t rn, uint8_t rt, bool isW = false);
                static insn new_register_mov(loc_t pc, int64_t imm, uint8_t rd, uint8_t rm, uint8_t rn = 0x1f);
                static insn new_register_msr(loc_t pc, uint8_t rt, systemreg sysreg, bool isMRS = false);

#pragma mark immediate
                static insn new_immediate_add(loc_t pc, int64_t imm, uint8_t rn, uint8_t rd);
                static insn new_immediate_b(loc_t pc, uint64_t imm);
                static insn new_immediate_bcond(loc_t pc, uint64_t imm, enum cond condition);
                static insn new_immediate_bl(loc_t pc, int64_t imm);
                static insn new_immediate_cbz(loc_t pc, loc_t imm, int8_t rt, bool isCBNZ = false);
                static insn new_immediate_cmp(loc_t pc, uint64_t imm, uint8_t rn);
                static insn new_immediate_ldr_unsigned(loc_t pc, int64_t imm, uint8_t rn, uint8_t rt, bool isW = false);
                static insn new_immediate_movk(loc_t pc, int64_t imm, uint8_t rd, uint8_t lsl, bool isW = false);
                static insn new_immediate_movz(loc_t pc, int64_t imm, uint8_t rd, uint8_t lsl, bool isW = false);
                static insn new_immediate_str_unsigned(loc_t pc, int64_t imm, uint8_t rn, uint8_t rt, bool isW = false);
                static insn new_immediate_strb_unsigned(loc_t pc, int64_t imm, uint8_t rn, uint8_t rt);
                static insn new_immediate_sub(loc_t pc, uint64_t imm, uint8_t rn, uint8_t rd);
                static insn new_immediate_subs(loc_t pc, uint64_t imm, uint8_t rn, uint8_t rd);
                static insn new_immediate_tbz(loc_t pc, int16_t imm, uint8_t b5, uint8_t b40, uint8_t rt, bool isTBNZ = false);
    
#pragma mark literal
                static insn new_literal_ldr(loc_t pc, uint64_t imm, uint8_t rt);
            };
        
        };
    };
};





#endif /* arm64_insn_hpp */
