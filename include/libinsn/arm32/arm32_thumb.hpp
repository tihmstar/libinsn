//
//  insn32_thumb.h
//  libinsn
//
//  Created by tihmstar on 09.10.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef insn32_thumb_h
#define insn32_thumb_h

#include <libinsn/arm32/arm32_insn.hpp>

namespace tihmstar{
    namespace libinsn{
        namespace arm32{
            class thumb {
            public:
                typedef uint32_t loc_t;
                typedef uint32_t offset_t;
            private:
                uint32_t _opcode;
                uint32_t _pc;
                enum type _type;
                enum subtype _subtype;
                enum supertype _supertype;

            public:
                thumb(uint32_t opcode, uint32_t pc);

            public:
                uint32_t opcode();
                uint32_t pc();
                
                enum cputype cputype();
                uint8_t insnsize() const;

                enum type type();
                enum subtype subtype();
                enum supertype supertype();
                int32_t imm();
                uint8_t rd();
                uint8_t rn();
                uint8_t rt();
    //            uint8_t rt2();
                uint8_t rm();
                enum cond condition();
    //            uint32_t special();
                register_list reglist();
                
            public: //cast operators
                operator enum type();
                operator loc_t();
                
#pragma mark constructor functions
            public: //constructor functions
#pragma mark general
                static thumb new_T1_general_nop(loc_t pc);
                static thumb new_T1_general_bx(loc_t pc, uint8_t rm);

#pragma mark register
                static thumb new_T2_register_mov(loc_t pc, uint8_t rd, uint8_t rm); //2 byte in size
                static thumb new_T3_register_mov(loc_t pc, uint8_t rd, uint8_t rm); //4 byte in size

#pragma mark immediate
                static thumb new_T1_immediate_bcond(loc_t pc, loc_t dst, enum cond condition); //2 byte in size
                static thumb new_T1_immediate_bl(loc_t pc, loc_t dst); //4 byte in size
                static thumb new_T1_immediate_cmp(loc_t pc, uint8_t imm, uint8_t rn); //2 byte
                static thumb new_T1_immediate_ldr(loc_t pc, uint8_t imm, uint8_t rn, uint8_t rt);
                static thumb new_T1_immediate_movs(loc_t pc, int8_t imm, uint8_t rd);
                static thumb new_T1_immediate_str(loc_t pc, int8_t imm, uint8_t rn, uint8_t rt);

                static thumb new_T2_immediate_b(loc_t pc, loc_t dst); //2 byte in size
                static thumb new_T2_immediate_cmp(loc_t pc, int32_t imm, uint8_t rn); //4 byte
                static thumb new_T2_immediate_ldr(loc_t pc, int16_t imm, uint8_t rt); //rn is SP
                static thumb new_T2_immediate_str(loc_t pc, int16_t imm, uint8_t rt); //rn is SP

#pragma mark literal
                static thumb new_T1_literal_ldr(loc_t pc, loc_t src, uint8_t rt); //2 byte in size

            };
        };
    };
};

#endif /* insn32_thumb_h */
