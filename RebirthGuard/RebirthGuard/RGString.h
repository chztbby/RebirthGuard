
/*
    chztbby::RebirthGuard/RGString.h
*/

#ifndef RGSTRING_H
#define RGSTRING_H

#include <array>

template <DWORD N, typename T, DWORD key>
class RGString
{
private:
    std::array<T, N> str_;

    constexpr T Xor(T c) const
    {
        return c ^ key;
    }

public:
    template <DWORD... IS>
    constexpr RGString(const T* str, std::index_sequence<IS...>)
    {
        str_ = { Xor(str[IS])... };
    }

    template <DWORD... IS>
    const T* Get(std::index_sequence<IS...>)
    {
        str_ = { Xor(str_[IS])... };

        return str_.data();
    }
};

#define MIS(s) (std::make_index_sequence<ARRAYSIZE(s)>())
#define XES(s) ([]{ constexpr RGString<ARRAYSIZE(s), std::decay<decltype(*s)>::type, __LINE__> t(s, MIS(s)); return t; }().Get(MIS(s)))

#endif