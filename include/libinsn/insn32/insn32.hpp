//
//  insn32.hpp
//  libinsn
//
//  Created by tihmstar on 09.10.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef insn32_hpp
#define insn32_hpp

#include <vector>
#include <stdint.h>


namespace tihmstar{
    namespace libinsn{
        class insn32{
        public: //type
            typedef uint32_t loc_t;
            typedef uint32_t offset_t;
            enum type{
                unknown = 0,
                lsl,
                lsr,
                asr,
                add,
                sub,
                mov,
                eor,
                cmp,
                and_,
                adc,
                sbc,
                ror,
                tst,
                rsb,
                cmn,
                orr,
                mul,
                bic,
                mvn,
                bx,
                blx,
                ldr,
                ldrh,
                ldrb,
                ldrsb,
                ldrsh,
                str,
                strh,
                strb,
                adr,
                cps,
                cbz,
                cbnz,
                sxth,
                sxtb,
                uxth,
                uxtb,
                push,
                pop,
                rev,
                rev16,
                revsh,
                bkpt,
                it,
                nop,
                yield,
                wfe,
                wfi,
                sev,
                stm,
                ldm,
                b,
                svc
            };
            enum cputype{
                cpu_thumb,
                cpu_arm
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
            
        protected:
            virtual ~insn32() = default;

        public:
            virtual uint32_t opcode() = 0;
            virtual uint32_t pc() = 0;

            virtual cputype cputype() = 0;
            virtual uint8_t insnsize() = 0;

             
            virtual type type() = 0;
            virtual subtype subtype() = 0;
            virtual supertype supertype() = 0;
//            virtual classtype classtype();
//            virtual int32_t imm() = 0;
//            virtual uint8_t rd() = 0;
//            virtual uint8_t rdn() = 0;
//            virtual uint8_t rn();
//            virtual uint8_t rt();
//            virtual uint8_t rt2();
//            virtual uint8_t rm() = 0;
//            virtual cond condition();
//            virtual uint32_t special();
//
//        public: //cast operators
//            virtual operator enum type();
//            virtual operator loc_t();
        };
    };
};

#endif /* insn32_hpp */
