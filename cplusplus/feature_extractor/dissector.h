#ifndef DISSECTOR_H
#define DISSECTOR_H
#include "macro.h"

class Dissector
{
public:
    static int is_tcp_begin(u_char flags)
    {
        if ((flags & TH_SYN) && !(flags & TH_ACK))
            return 1;
        return 0;
    }
    static int is_tcp_sec(u_char flags)
    {
        if ((flags & TH_SYN) && (flags & TH_ACK))
            return 1;
        return 0;
    }
    static int is_tcp_third(u_char flags)
    {
        if (!(flags & TH_SYN) && (flags & TH_ACK))
            return 1;
        return 0;
    }
    static bool is_tcp_new(u_char flags)
    {
        return is_tcp_begin(flags);
    }
};

#endif

