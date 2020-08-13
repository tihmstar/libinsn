//
//  insn.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef insn_hpp
#define insn_hpp

#include <vector>
#include <stdint.h>

namespace tihmstar{
    namespace libinsn{
        typedef uint64_t loc_t;
        typedef uint64_t offset_t;

        class insn{
        public: //type
            enum type{
                unknown = 0,
                adrp,
                adr,
                bl,
                cbz,
                ret,
                tbnz,
                add,
                sub,
                br,
                blr,
                ldr,
                ldrh,
                cbnz,
                movk,
                orr,
                tbz,
                ldxr,
                ldrb,
                str,
                strb,
                stp,
                ldp,
                movz,
                bcond,
                b,
                nop,
                and_,
                csel,
                mov,
                mrs,
                subs,
                cmp = subs,
                ccmp,
                madd,
                pacib,
                pacizb,
                pacibsp,
                msr
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
                tpidr_el1   = 0x4684,
                sctlr_el1   = 0x4080,
                tcr_el1     = 0x4102,
                ttbr0_el1   = 0x4100
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
            
            type type();
            subtype subtype();
            supertype supertype();
            pactype pactype();
            int64_t imm();
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
            
              
#pragma mark constructor functions
        public: //constructor functions
#pragma mark general
            static insn new_general_adr(loc_t pc, uint64_t imm, uint8_t rd);
            static insn new_general_adrp(loc_t pc, uint64_t imm, uint8_t rd);
            static insn new_general_br(loc_t pc, uint8_t rn, uint8_t rm = 0, enum pactype pac = pac_none);
            static insn new_general_ldp(loc_t pc, int8_t imm, uint8_t rt, uint8_t rt2, uint8_t rn, bool isPreindex = false);
            static insn new_general_stp(loc_t pc, int8_t imm, uint8_t rt, uint8_t rt2, uint8_t rn, bool isPreindex = false);
            static insn new_general_nop(loc_t pc);
            static insn new_general_ret(loc_t pc);

#pragma mark register
            static insn new_register_ccmp(loc_t pc, cond condition, uint8_t flags, uint8_t rn, uint8_t rm);
            static insn new_register_mov(loc_t pc, int64_t imm, uint8_t rd, uint8_t rn, uint8_t rm);

#pragma mark immediate
            static insn new_immediate_add(loc_t pc, uint64_t imm, uint8_t rn, uint8_t rd);
            static insn new_immediate_b(loc_t pc, uint64_t imm);
            static insn new_immediate_bcond(loc_t pc, uint64_t imm, enum cond condition);
            static insn new_immediate_bl(loc_t pc, int64_t imm);
            static insn new_immediate_cbz(loc_t pc, int32_t imm, int8_t rt, bool isCBNZ = false);
            static insn new_immediate_ldr(loc_t pc, int64_t imm, uint8_t rn, uint8_t rt);
            static insn new_immediate_movk(loc_t pc, int64_t imm, uint8_t rd, uint8_t rm);
            static insn new_immediate_movz(loc_t pc, int64_t imm, uint8_t rd, uint8_t rm);
            static insn new_immediate_tbz(loc_t pc, int16_t imm, uint8_t b5, uint8_t b40, uint8_t rt, bool isTBNZ = false);

#pragma mark literal
            static insn new_literal_ldr(loc_t pc, uint64_t imm, uint8_t rt);
        };
    };
};





#endif /* insn_hpp */
