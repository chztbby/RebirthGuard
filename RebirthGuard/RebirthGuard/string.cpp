
/*
	chztbby::RebirthGuard/string.cpp
*/

#include "RebirthGuard.h"

LPSTR RG_strcat(LPSTR s1, LPCSTR s2)
{
	LPSTR cp = s1;
	while (*cp != '\0')
		cp++;
	while ((*cp++ = *s2++) != '\0');

	return (s1);
}

LPCWSTR RG_wcsistr(LPCWSTR s1, LPCWSTR s2)
{
	if (s1 && s2)
	{
		LPCWSTR s;
		LPCWSTR sub;
		for (; *s1; s1++)
		{
			for (sub = s2, s = s1; *sub && *s; sub++, s++)
			{
				WCHAR ms, msub;
				if (*s >= 'a' && *s <= 'z')	ms = *s - 0x20;
				else						ms = *s;
				if (*sub >= 'a' && *sub <= 'z') msub = *sub - 0x20;
				else							msub = *sub;
				if (ms != msub) break;
			}

			if (*sub == 0)
				return s1;
		}
	}
	return NULL;
}

LPWSTR RG_wcscpy(LPWSTR s1, LPCWSTR s2)
{
	LPWSTR cp = s1;
	while ((*cp++ = *s2++) != L'\0');

	return (s1);
}

LPWSTR RG_wcscat(LPWSTR s1, LPCWSTR s2)
{
	LPWSTR cp = s1;
	while (*cp != L'\0')
		cp++;
	while ((*cp++ = *s2++) != L'\0');

	return (s1);
}