//
//  insn32.hpp
//  libinsn
//
//  Created by tihmstar on 09.10.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef arm32_insn_hpp
#define arm32_insn_hpp

#include <stdint.h>

#ifdef stc2
#undef stc2 //already defined on windows in dlgs.h
#endif

namespace tihmstar{
    namespace libinsn{
        namespace arm32{
            enum type{
                unknown = 0,
                /* A */
                adc, add, adr, and_, asr,
                /* B */
                b, bcond, bfc, bfi, bic, bkpt, bl, blx, bx, bxj,
                /* C */
                cbnz, cbz, cdp, cdp2, clrex, clz, cmn, cmp, cps,
                /* D */
                dbg, dmb, dsb,
                /* E */
                eor, eret,
                /* H */
                hvc,
                /* I */
                isb, it,
                /* L */
                ldc, ldc2,
                ldm, ldmda, ldmdb, ldmea, ldmed, ldmfa, ldmfd, ldmia, ldmib,
                ldr, ldrb, ldrbt, ldrd, ldrex, ldrexb, ldrexd, ldrexh, ldrh, ldrht, ldrsb, ldrsbt, ldrsh, ldrsht, ldrt,
                lsl, lsr,
                /* M */
                mcr, mcr2, mcrr, mcrr2,
                mla, mls,
                mov, movt,
                mrc, mrc2, mrrc, mrrc2, mrs,
                msr,
                mul,
                mvn,
                /* N */
                nop,
                /* O */
                orn, orr,
                /* P */
                pkh, pld, pli, pop, push,
                /* Q */
                qadd, qadd16, qadd8, qasx,
                qdadd, qdsub,
                qsax, qsub, qsub16, qsub8,
                /* R */
                rbit, rev, rev16, revsh, rfe, ror, rrx, rsb, rsc,
                /* S */
                sadd16, sadd8, sasx,
                sbc, sbfx,
                sdiv,
                sel, setend, sev,
                shadd16, shadd8, shasx, shsax, shsub16, shsub8,
                smc, smlad, smlal, smlald, smlsd, smlsld, smmla, smmls, smmul, smuad, smull, smusd,
                srs,
                ssat, ssat16, ssax, ssub16, ssub8,
                stc, stc2,
                stm, stmda, stmdb, stmea, stmed, stmfa, stmfd, stmia, stmib,
                str, strb, strbt, strd, strex, strexb, strexd, strexh, strh, strht, strt,
                sub,
                svc,
                swp, swpb,
                sxtab, sxtab16, sxtah, sxtb, sxtb16, sxth,
                /* T */
                teq, tst, ttb, tth,
                /* U */
                uadd16, uadd8, uasx,
                ubfx,
                udf, udiv,
                uhadd16, uhadd8, uhasx, uhsax, uhsub16, uhsub8,
                umaal, umlal, umull,
                uqadd16, uqadd8, uqasx, uqsax, uqsub16, uqsub8,
                usad8, usada8, usat, usat16, usax, usub16, usub8,
                uxtab, uxtab16, uxtah, uxtb, uxtb16, uxth,
                /* V */
                vldm, vldr, vmov, vpop, vpush, vstm, vstr,
                /* W */
                wfe, wfi,
                /* Y */
                yield
            };
            enum cputype{
                cpu_thumb,
                cpu_arm
            };
            enum subtype{
                st_general,
                st_register,
                st_register_shifted_register,
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
            struct register_list{
                uint16_t r0 : 1;
                uint16_t r1 : 1;
                uint16_t r2 : 1;
                uint16_t r3 : 1;
                uint16_t r4 : 1;
                uint16_t r5 : 1;
                uint16_t r6 : 1;
                uint16_t r7 : 1;
                uint16_t r8 : 1;
                uint16_t r9 : 1;
                uint16_t r10 : 1;
                uint16_t r11 : 1;
                uint16_t r12 : 1;
                uint16_t sp : 1;
                uint16_t lr : 1;
                uint16_t pc : 1;
            };
        };
    };
};

#endif /* arm32_insn_hpp */
