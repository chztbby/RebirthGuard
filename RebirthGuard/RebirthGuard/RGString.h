
/*
    chztbby::RebirthGuard/RGString.h
*/

#ifndef RGSTRING_H
#define RGSTRING_H

#if __cplusplus >= 201703
#include <array>

template <typename T, SIZE_T N, SIZE_T K>
class RGString
{
private:
    std::array<T, N> str_;

    __forceinline constexpr T Xor(T c) const
    {
        return (T)(c ^ K);
    }

public:
    template <SIZE_T... IS>
    __forceinline constexpr RGString(const T* str, std::index_sequence<IS...>) : str_{ Xor(str[IS])... } {};

    template <SIZE_T... IS>
    __forceinline const T* Get(std::index_sequence<IS...>)
    {
        str_ = { Xor(str_[IS])... };

        return str_.data();
    }
};

#define MIS(s) (std::make_index_sequence<ARRAYSIZE(s)>())
#define RGS(s) ([]{ constexpr RGString<std::decay<decltype(*s)>::type, ARRAYSIZE(s), __LINE__> t(s, MIS(s)); return t; }().Get(MIS(s)))
#else
#define MIS(s) (s)
#define RGS(s) (s)
#endif

#endif