//
//  INSNexception.h
//  libinsn
//
//  Created by tihmstar on 17.03.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef INSNexception_h
#define INSNexception_h

#include <libgeneral/macros.h>
#include <libgeneral/exception.hpp>


namespace tihmstar {
    class INSNexception : public tihmstar::exception{
        using exception::exception;
    };

//custom exceptions for makeing it easy to catch
    class out_of_range : public INSNexception{
        using INSNexception::INSNexception;
    };


};

#endif /* INSNexception_h */
