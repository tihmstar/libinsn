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
                pacibsp
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
                NE = 000,
                EG = 000,
                CS = 001,
                CC = 001,
                MI = 010,
                PL = 010,
                VS = 011,
                VC = 011,
                HI = 100,
                LS = 100,
                GE = 101,
                LT = 101,
                GT = 110,
                LE = 110,
                AL = 111
            };
            enum systemreg : uint64_t{
                tpidr_el1 = 0x4684
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
            
              
        public: //constructor functions
            static insn new_general_adr(loc_t pc, uint64_t imm, uint8_t rd);
            static insn new_general_adrp(loc_t pc, uint64_t imm, uint8_t rd);

            static insn new_register_mov(loc_t pc, int64_t imm, uint8_t rd, uint8_t rn, uint8_t rm);
            static insn new_register_ccmp(loc_t pc, cond condition, uint8_t flags, uint8_t rn, uint8_t rm);

            static insn new_immediate_add(loc_t pc, uint64_t imm, uint8_t rn, uint8_t rd);
            static insn new_immediate_bl(loc_t pc, int64_t imm);
            static insn new_immediate_b(loc_t pc, uint64_t imm);
            static insn new_immediate_movz(loc_t pc, int64_t imm, uint8_t rd, uint8_t rm);
            static insn new_immediate_movk(loc_t pc, int64_t imm, uint8_t rd, uint8_t rm);
            static insn new_immediate_ldr(loc_t pc, int64_t imm, uint8_t rn, uint8_t rt);
        };
    };
};





#endif /* insn_hpp */
