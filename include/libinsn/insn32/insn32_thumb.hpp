//
//  insn32_thumb.h
//  libinsn
//
//  Created by tihmstar on 09.10.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef insn32_thumb_h
#define insn32_thumb_h

#include <libinsn/insn32/insn32.hpp>

namespace tihmstar{
    namespace libinsn{
        class insn32_thumb : public insn32 {
        private:
            uint32_t _opcode;
            uint32_t _pc;
            enum type _type;
            enum subtype _subtype;
            enum supertype _supertype;

        public:
            insn32_thumb(uint32_t opcode, uint32_t pc);
            virtual ~insn32_thumb() override;

        public:
            virtual uint32_t opcode() override;
            virtual uint32_t pc() override;
            
            virtual enum cputype cputype() override;
            virtual uint8_t insnsize() override;

            virtual enum type type() override;
            virtual enum subtype subtype() override;
            virtual enum supertype supertype() override;
//            enum classtype classtype();
//            virtual int32_t imm() override;
//            virtual uint8_t rd() override;
//            uint8_t rn();
//            uint8_t rt();
//            uint8_t rt2();
//            virtual uint8_t rm() override;
//            enum cond condition();
//            uint32_t special();
//            
//        public: //cast operators
//            operator enum type();
//            operator loc_t();
        };
    };
};

#endif /* insn32_thumb_h */
